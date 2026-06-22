package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/realtime"
)

// agentWorkflowInflight 保证同一事件的分析同一时刻只跑一条，避免「查看报告」重推
// 与摄入路径并发触发两次 LLM 调用。
var agentWorkflowInflight sync.Map // eventID -> struct{}

// RunAgentWorkflowAsync 在后台跑事件分析，并与 HTTP 请求上下文解耦：
// 分析依赖 LLM、耗时较长，绝不能因请求返回/前端超时而被取消（否则报告页会看到
// "context canceled"）。限时由 LLM 客户端自身的 http.Client.Timeout 负责；进度/结果
// 通过 realtime 广播与消息流回传，前端用 websocket 增量渲染。
func (s Services) RunAgentWorkflowAsync(eventID string) {
	if strings.TrimSpace(eventID) == "" {
		return
	}
	if _, running := agentWorkflowInflight.LoadOrStore(eventID, struct{}{}); running {
		return
	}
	go func() {
		defer agentWorkflowInflight.Delete(eventID)
		_ = s.RunAgentWorkflow(context.Background(), eventID)
	}()
}

func (s Services) RunAgentWorkflow(ctx context.Context, eventID string) error {
	event, ok := s.Store.GetEvent(eventID)
	if !ok {
		return fmt.Errorf("event not found: %s", eventID)
	}
	roundID := event.CurrentRound
	if roundID == 0 {
		roundID = 1
	}
	if hasAgentWorkflowMessages(s.Store.ListMessages(eventID)) {
		return nil
	}

	_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "processing"})

	health := s.LLM.HealthCheck(ctx)
	if !health.Configured || !health.OK {
		err := fmt.Errorf("LLM不可用，请先在配置页面填写并验证可用的LLM参数: %s", firstNonEmpty(health.Error, "health check failed"))
		_ = s.addLLMConfigRequiredMessage(eventID, roundID, err.Error())
		// 事件状态回到 pending：列表里显示「未分析/待分析」而不是「需配置LLM」。
		// LLM 修好后会自动重试（RoleSystem 提示消息不计入 hasAgentWorkflowMessages）；
		// 「需配置LLM」的提示仍通过消息流与实时广播在报告详情里呈现。
		_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "pending"})
		realtime.BroadcastStatus(eventID, map[string]any{"event_id": eventID, "status": "llm_config_required", "message": err.Error()})
		return err
	}

	reply, err := s.LLM.Chat(ctx, autoAnalysisPrompt(event))
	if err != nil {
		err = fmt.Errorf("LLM自动分析失败，请检查LLM配置: %w", err)
		_ = s.addLLMConfigRequiredMessage(eventID, roundID, err.Error())
		// 同上：保持 pending（列表显示未分析），等 LLM 恢复后自动重试。
		_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "pending"})
		realtime.BroadcastStatus(eventID, map[string]any{"event_id": eventID, "status": "llm_config_required", "message": err.Error()})
		return err
	}

	sm, err := s.Store.AddSummary(domain.Summary{EventID: eventID, RoundID: roundID, EventSummary: reply})
	if err != nil {
		return err
	}
	_ = s.addAgentMessage(eventID, domain.RoleExpert, "event_summary", roundID,
		llmExpertResponse(event, roundID, sm, reply))
	_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "round_finished"})
	realtime.BroadcastStatus(eventID, map[string]any{"event_id": eventID, "status": "round_finished"})
	return nil
}

func (s Services) addLLMConfigRequiredMessage(eventID string, roundID int, text string) error {
	return s.addAgentMessage(eventID, domain.RoleSystem, "llm_config_required", roundID, map[string]any{
		"type":          "llm_config_required",
		"event_id":      eventID,
		"round_id":      roundID,
		"response_text": text,
	})
}

func autoAnalysisPrompt(event domain.Event) string {
	return fmt.Sprintf(`你是 DeepSOC 自动分析引擎。请仅基于下面的安全事件信息生成自动分析结果，不要编造未提供的日志、资产或情报事实。

输出要求：
1. 使用中文 Markdown。
2. 保持原版 DeepSOC 自动驾驶分析风格，覆盖 Captain 研判、Manager 动作拆解、Operator 命令建议、Executor 应由外部剧本验证的证据项、Expert 总结。
3. 明确区分“已知事实”“待验证证据”“建议执行动作”，不要把未执行的剧本结果写成已完成。
4. 充分结合下方「辅助研判信息」中的应用层证据（HTTP 方法/URL/User-Agent/请求头/请求体、DNS 查询与应答、payload 样本）、流量方向、流统计与威胁情报命中元数据，进行：威胁真假研判（是否误报）、攻击手法定性、影响面与横向风险评估、以及有针对性的处置/取证建议。
5. 如果信息不足，必须写清缺口和下一步需要查询的数据。

事件ID：%s
事件名称：%s
严重级别：%s
来源：%s
描述：%s
可观察对象：%s

辅助研判信息（融合采集节点 ta_node 解析的应用层与情报上下文）：
%s

原始上下文(JSON)：%s`,
		event.EventID,
		firstNonEmpty(event.EventName, event.Title, "未命名事件"),
		firstNonEmpty(event.Severity, "unknown"),
		firstNonEmpty(event.Source, "unknown"),
		firstNonEmpty(event.Message, "无"),
		formatObservables(event.Observables),
		formatAuxContext(event.Context),
		firstNonEmpty(event.Context, "无"),
	)
}

// formatAuxContext 将事件 context(JSON) 中来自 ta_node 的辅助信息抽取为
// 可读的中文 Markdown 列表，突出应用层证据/流量方向/情报元数据，便于模型详细研判。
// 当无附加信息时返回 "无"。
func formatAuxContext(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "无"
	}
	var ctx map[string]any
	if err := json.Unmarshal([]byte(raw), &ctx); err != nil {
		return "无"
	}

	var b strings.Builder
	emit := func(indent, label string, v any) {
		s := scalarString(v)
		if s == "" {
			return
		}
		fmt.Fprintf(&b, "%s- %s：%s\n", indent, label, s)
	}

	// 流量方向（含语义说明，帮助模型判断外联/横向风险）
	switch asString(ctx["direction"]) {
	case "inbound":
		emit("", "流量方向", "inbound（外部→内网，入站攻击）")
	case "outbound":
		emit("", "流量方向", "outbound（内网→外部，出站，警惕外联/数据外传）")
	case "lateral":
		emit("", "流量方向", "lateral（内网→内网，警惕横向移动）")
	case "external":
		emit("", "流量方向", "external（外部→外部）")
	default:
		emit("", "流量方向", ctx["direction"])
	}

	// 流统计
	if fs, ok := ctx["flow_stats"].(map[string]any); ok && len(fs) > 0 {
		emit("", "流持续时长(ms)", fs["duration_ms"])
		emit("", "流首次时间(epoch)", fs["first_time"])
		if line := joinKV(fs, []string{"flows", "packets", "bytes"}, " "); line != "" {
			emit("", "流/包/字节", line)
		}
	}

	// 应用层证据
	if app, ok := ctx["app"].(map[string]any); ok && len(app) > 0 {
		b.WriteString("- 应用层证据(app)：\n")
		emit("  ", "HTTP 方法", app["http_method"])
		emit("  ", "HTTP Host", app["http_host"])
		emit("  ", "HTTP URL", app["http_url"])
		emit("  ", "User-Agent", app["user_agent"])
		if h, ok := app["http_headers"].(map[string]any); ok && len(h) > 0 {
			emit("  ", "请求头", kvJoin(h))
		}
		emit("  ", "请求体样本", app["http_body_sample"])
		emit("  ", "DNS 查询", app["dns_query"])
		emit("  ", "DNS 类型", app["dns_qtype"])
		emit("  ", "DNS 应答", listJoin(app["dns_answers"]))
		emit("  ", "Payload 样本", app["payload_sample"])
		emit("  ", "ICMP 序列号", app["icmp_seq"])
	}

	// 威胁情报命中元数据
	if ioc, ok := ctx["ioc"].(map[string]any); ok && len(ioc) > 0 {
		b.WriteString("- 威胁情报命中(ioc)：\n")
		emit("  ", "类型", ioc["ioc_type"])
		emit("  ", "命中值", ioc["ioc_value"])
		emit("  ", "类别", ioc["ioc_category"])
		emit("  ", "情报源", ioc["ioc_source"])
		emit("  ", "标签", listJoin(ioc["ioc_tags"]))
		emit("  ", "描述", ioc["ioc_description"])
		emit("  ", "过期时间(epoch)", ioc["ioc_expire_at"])
	}

	// 其它元数据
	emit("", "威胁指数", ctx["threat_index"])
	emit("", "检测模型", ctx["detection_model"])
	emit("", "证据文件", ctx["evidence_file"])
	emit("", "Schema 版本", ctx["schema_version"])
	emit("", "传感器版本", ctx["sensor_version"])

	if b.Len() == 0 {
		return "无"
	}
	return strings.TrimRight(b.String(), "\n")
}

// scalarString 把任意标量渲染为字符串；空值/空容器返回 ""。
func scalarString(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		// JSON 数字统一为 float64；整数去掉小数点。
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		return fmt.Sprintf("%v", t)
	default:
		return ""
	}
}

// joinKV 按给定键序把 m 中存在的数值/标量拼成 "k=v" 串。
func joinKV(m map[string]any, keys []string, sep string) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if s := scalarString(m[k]); s != "" {
			parts = append(parts, k+"="+s)
		}
	}
	return strings.Join(parts, sep)
}

// kvJoin 把 map（如请求头）渲染为按键排序的 "k=v" 串。
func kvJoin(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if s := scalarString(m[k]); s != "" {
			parts = append(parts, k+"="+s)
		}
	}
	return strings.Join(parts, "; ")
}

// listJoin 把数组（dns_answers / ioc_tags 等）渲染为逗号分隔串。
func listJoin(v any) string {
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return ""
	}
	parts := make([]string, 0, len(arr))
	for _, item := range arr {
		if s := scalarString(item); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ", ")
}

func formatObservables(items []domain.IOC) string {
	if len(items) == 0 {
		return "无"
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, fmt.Sprintf("- type=%s role=%s value=%s", item.Type, item.Role, item.Value))
	}
	return strings.Join(lines, "\n")
}

func llmExpertResponse(event domain.Event, roundID int, sm domain.Summary, reply string) map[string]any {
	return map[string]any{
		"type":          "llm_response",
		"from":          domain.RoleExpert,
		"to":            []string{domain.RoleCaptain},
		"event_id":      event.EventID,
		"round_id":      roundID,
		"response_type": "SUMMARY",
		"response_text": reply,
		"suggestions":   []string{"当前结果由已配置 LLM 生成；如需执行封禁、取证或资产查询，请接入对应外部剧本/执行器。"},
	}
}

func hasAgentWorkflowMessages(messages []domain.Message) bool {
	for _, msg := range messages {
		switch NormalizeMessageFrom(msg.MessageFrom) {
		case domain.RoleCaptain, domain.RoleManager, domain.RoleOperator, domain.RoleExecutor, domain.RoleExpert:
			return true
		}
	}
	return false
}

func (s Services) addAgentMessage(eventID, from, messageType string, roundID int, data any) error {
	from = NormalizeMessageFrom(from)
	m, err := s.Store.AddMessage(domain.Message{
		EventID:         eventID,
		MessageFrom:     from,
		MessageType:     messageType,
		MessageContent:  StandardContent(data),
		RoundID:         roundID,
		MessageCategory: "agent",
		SenderType:      SenderType(from),
	})
	if err == nil {
		realtime.BroadcastMessage(eventID, m)
		_ = s.publish(context.Background(), "notifications.frontend."+eventID+"."+from+"."+messageType, eventID, from, m)
	}
	return err
}
