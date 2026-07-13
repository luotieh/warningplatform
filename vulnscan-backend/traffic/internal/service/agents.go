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

	reply, err := s.LLM.Chat(ctx, autoAnalysisSystemPrompt, autoAnalysisPrompt(event))
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
		return s.failAgentWorkflow(eventID, fmt.Errorf("保存分析总结失败: %w", err))
	}
	// 专家消息写库失败必须让状态如实反映：吞掉错误仍标记 round_finished 会出现
	// “列表显示已生成、报告里却只有创建事件”的假完成状态。
	if err := s.addAgentMessage(eventID, domain.RoleExpert, "event_summary", roundID,
		llmExpertResponse(event, roundID, sm, reply)); err != nil {
		return s.failAgentWorkflow(eventID, fmt.Errorf("保存专家分析消息失败: %w", err))
	}
	_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "round_finished"})
	realtime.BroadcastStatus(eventID, map[string]any{"event_id": eventID, "status": "round_finished"})
	return nil
}

// failAgentWorkflow 把事件置为 failed 并广播失败详情；列表显示“分析失败”，
// 且不阻断重试（专家消息未落库时 hasAgentWorkflowMessages 仍为 false，重推可再跑）。
func (s Services) failAgentWorkflow(eventID string, err error) error {
	_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "failed"})
	realtime.BroadcastStatus(eventID, map[string]any{"event_id": eventID, "status": "failed", "message": err.Error()})
	return err
}

func (s Services) addLLMConfigRequiredMessage(eventID string, roundID int, text string) error {
	return s.addAgentMessage(eventID, domain.RoleSystem, "llm_config_required", roundID, map[string]any{
		"type":          "llm_config_required",
		"event_id":      eventID,
		"round_id":      roundID,
		"response_text": text,
	})
}

// autoAnalysisSystemPrompt 是自动分析链路专用的精简 system(不复用工程师对话人格)。
const autoAnalysisSystemPrompt = `你是 DeepSOC 安全运营自动分析引擎。仅基于给定的安全事件信息研判，不得编造未提供的日志、资产或情报事实。输出简体中文 Markdown。`

func autoAnalysisPrompt(event domain.Event) string {
	obsStr := formatObservables(event.Observables)
	auxStr := formatAuxContext(event.Context)

	// 兜底:事件数据(可观察对象 + 辅助研判信息)整体不超预算;超了先压缩体量更大、
	// 更可变的辅助信息块(逐字段截断已在 formatAuxContext 内做,此处是最后一道防线)。
	if estimateTokens(obsStr)+estimateTokens(auxStr) > eventDataBudgetTokens {
		auxStr = fitToTokenBudget(auxStr, eventDataBudgetTokens-estimateTokens(obsStr))
	}

	return fmt.Sprintf(`# 安全事件
事件ID：%s
事件名称：%s
严重级别：%s
来源：%s
描述：%s

## 可观察对象
%s

## 辅助研判信息（融合采集节点 ta_node 解析的应用层与情报上下文）
%s

# 分析要求
结合上方证据完成研判：威胁真假（是否误报）、攻击手法定性、影响面与横向风险、处置建议。
- 利用「通联方向」（to_ioc=数据外传、from_ioc=载荷下载）与流量体量判断外传/下载/beacon；
- local_hit_count 仅为节点近似分诊提示，权威全局频次以 occurrence_count 为准，勿重复计数；
- 若事件带「建议处置(情报侧)」，需明确采纳或修正并说明理由；
- 信息不足时写清缺口与下一步应查询的数据；不要把未执行的剧本结果写成已完成。

# 输出格式（严格遵守）
第一行必须输出以【结论】开头的一句话总结，先给结论再展开；禁止复述输入信息、禁止第一人称思考过程、禁止输出模板外内容。

【结论】<一句话：研判定性(误报/探测/利用尝试/有效入侵) + 核心依据 + 建议动作>

## 研判结论
## 关键证据
## 影响与风险
## 建议处置
## 信息缺口`,
		event.EventID,
		firstNonEmpty(event.EventName, event.Title, "未命名事件"),
		firstNonEmpty(event.Severity, "unknown"),
		firstNonEmpty(event.Source, "unknown"),
		firstNonEmpty(event.Message, "无"),
		obsStr,
		auxStr,
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

	// 流统计 / 通联数据量
	if fs, ok := ctx["flow_stats"].(map[string]any); ok && len(fs) > 0 {
		emit("", "流持续时长(ms)", fs["duration_ms"])
		emit("", "流首次时间(epoch)", fs["first_time"])
		if line := joinKV(fs, []string{"flows", "packets", "bytes", "wire_bytes"}, " "); line != "" {
			emit("", "流量体量", line+"（bytes=载荷字节, wire_bytes=在线字节含L2-L4头）")
		}
		switch asString(fs["volume_role"]) {
		case "to_ioc":
			emit("", "通联方向", "to_ioc（数据流向 IOC，疑似数据外传/上传）")
		case "from_ioc":
			emit("", "通联方向", "from_ioc（数据来自 IOC，疑似载荷下载）")
		default:
			emit("", "通联方向", fs["volume_role"])
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
		emit("  ", "请求体样本", truncateRunes(scalarString(app["http_body_sample"]), auxSampleMaxRunes))
		emit("  ", "DNS 查询", app["dns_query"])
		emit("  ", "DNS 类型", app["dns_qtype"])
		emit("  ", "DNS 应答", listJoin(app["dns_answers"]))
		emit("  ", "Payload 样本", truncateRunes(scalarString(app["payload_sample"]), auxSampleMaxRunes))
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

	// 情报富化证据（intel 命中且情报带该数据时出现）
	if ie, ok := ctx["ioc_evidence"].(map[string]any); ok && len(ie) > 0 {
		b.WriteString("- 情报富化证据(ioc_evidence)：\n")
		emit("  ", "关联活动/战役", ie["activity"])
		emit("  ", "威胁标签", listJoin(ie["threat_labels"]))
		emit("  ", "情报来源", ie["source"])
		emit("  ", "交叉验证", ie["cross_check"])
		emit("  ", "置信度", ie["confidence"])
		emit("  ", "TLP", ie["tlp"])
		emit("  ", "MISP 事件", ie["misp_event_id"])
		emit("  ", "告警叙述", truncateRunes(scalarString(ie["narrative"]), auxNarrativeMaxRunes))
	}

	// 情报侧建议处置（供模型在「建议处置」环节采纳/修正）
	emit("", "建议处置(情报侧)", ctx["recommended_action"])

	// 节点侧局部突发计数（近似分诊提示，非全局权威频次：全局频次见上方/原始上下文的 occurrence_count）
	if lb, ok := ctx["local_burst"].(map[string]any); ok && len(lb) > 0 {
		b.WriteString("- 节点侧局部突发(local_burst，近似分诊提示，非全局频次)：\n")
		emit("  ", "本节点窗口内命中次数", lb["local_hit_count"])
		emit("  ", "统计窗口(秒)", lb["local_window_sec"])
		emit("  ", "首次命中(epoch)", lb["local_first_seen"])
		emit("  ", "计数范围", lb["local_scope"])
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
	shown := items
	omitted := 0
	if len(items) > maxObservables {
		shown = items[:maxObservables]
		omitted = len(items) - maxObservables
	}
	lines := make([]string, 0, len(shown)+1)
	for _, item := range shown {
		lines = append(lines, fmt.Sprintf("- type=%s role=%s value=%s", item.Type, item.Role, item.Value))
	}
	if omitted > 0 {
		lines = append(lines, fmt.Sprintf("- …(共 %d 条,省略 %d 条)", len(items), omitted))
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
