package service

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/realtime"
)

// agentWorkflowInflight 保证同一事件的分析同一时刻只跑一条，避免「查看报告」重推
// 与摄入路径并发触发两次 LLM 调用。
var agentWorkflowInflight sync.Map // eventID -> struct{}

// 分析类型（与 Summary.Kind / Event.AnalysisVersion 对应）。
const (
	AnalysisKindInitial = "initial"
	AnalysisKindFinal   = "final"
	AnalysisKindManual  = "manual"
)

// manualRefreshCooldown 手动刷新冷却窗口，防止高频重跑 LLM。
const manualRefreshCooldown = 60 * time.Second

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
	return s.runAnalysis(ctx, eventID, AnalysisKindInitial, 1)
}

// RunFinalAnalysis 收敛终报：仅在事件已收敛且尚未生成终版（version>=2）时执行。
func (s Services) RunFinalAnalysis(ctx context.Context, eventID string) error {
	event, ok := s.Store.GetEvent(eventID)
	if !ok {
		return fmt.Errorf("event not found: %s", eventID)
	}
	if !event.AggregationClosed {
		return fmt.Errorf("事件尚未收敛，无法生成终版分析")
	}
	if event.AnalysisVersion >= 2 {
		return nil
	}
	return s.runAnalysis(ctx, eventID, AnalysisKindFinal, 2)
}

// RefreshAnalysis 按需手动刷新：基于当前最新 quant_stats 重新生成分析，
// 新版本号 = 当前版本 + 1（kind=manual），受冷却窗口限制。
func (s Services) RefreshAnalysis(ctx context.Context, eventID string) (int, error) {
	event, ok := s.Store.GetEvent(eventID)
	if !ok {
		return 0, fmt.Errorf("event not found: %s", eventID)
	}
	if event.LastAnalysisAt != nil && time.Since(*event.LastAnalysisAt) < manualRefreshCooldown {
		remaining := int64(manualRefreshCooldown.Seconds()) - int64(time.Since(*event.LastAnalysisAt).Seconds())
		if remaining < 1 {
			remaining = 1
		}
		return 0, fmt.Errorf("手动刷新过于频繁，请 %d 秒后重试",
			remaining)
	}
	version := event.AnalysisVersion + 1
	if version < 3 {
		version = 3
	}
	if err := s.runAnalysis(ctx, eventID, AnalysisKindManual, version); err != nil {
		return 0, err
	}
	return version, nil
}

// RefreshAnalysisAsync 后台异步手动刷新：使用 context.Background() 运行分析，
// 避免前端请求超时/断开导致 LLM 调用被取消（context canceled while reading body）。
// 返回是否已开始（false 表示该事件正在分析中或事件不存在）。
func (s Services) RefreshAnalysisAsync(eventID string) bool {
	if strings.TrimSpace(eventID) == "" {
		return false
	}
	if _, ok := s.Store.GetEvent(eventID); !ok {
		return false
	}
	if _, running := agentWorkflowInflight.LoadOrStore(eventID, struct{}{}); running {
		return false
	}
	go func() {
		defer agentWorkflowInflight.Delete(eventID)
		_, _ = s.RefreshAnalysis(context.Background(), eventID)
	}()
	return true
}

// RunFinalAnalysisAsync 后台执行收敛终报，与请求上下文解耦。
func (s Services) RunFinalAnalysisAsync(eventID string) {
	if strings.TrimSpace(eventID) == "" {
		return
	}
	if _, running := agentWorkflowInflight.LoadOrStore(eventID, struct{}{}); running {
		return
	}
	go func() {
		defer agentWorkflowInflight.Delete(eventID)
		_ = s.RunFinalAnalysis(context.Background(), eventID)
	}()
}

// runAnalysis 版本化分析主流程：
//   - initial：已分析过（version>=1）则跳过；
//   - final：已生成终版（version>=2）则跳过（调用方已检查，此处兜底）；
//   - manual：强制重跑（冷却由 RefreshAnalysis 控制）。
func (s Services) runAnalysis(ctx context.Context, eventID string, kind string, version int) error {
	event, ok := s.Store.GetEvent(eventID)
	if !ok {
		return fmt.Errorf("event not found: %s", eventID)
	}
	// 兼容升级前已分析过的旧事件：无版本号但已有 agent 工作流消息时视为已分析。
	if kind == AnalysisKindInitial && (event.AnalysisVersion >= 1 || hasAgentWorkflowMessages(s.Store.ListMessages(eventID))) {
		return nil
	}
	if kind == AnalysisKindFinal && event.AnalysisVersion >= 2 {
		return nil
	}
	roundID := event.CurrentRound
	if roundID == 0 {
		roundID = 1
	}

	_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "processing"})

	if s.LLM == nil {
		err := fmt.Errorf("LLM未配置")
		_ = s.addLLMConfigRequiredMessage(eventID, roundID, err.Error())
		_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "pending"})
		realtime.BroadcastStatus(eventID, map[string]any{"event_id": eventID, "status": "llm_config_required", "message": err.Error()})
		return err
	}
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

	evidenceContext, err := s.EvidenceContext(ctx, event)
	if err != nil {
		return s.failAgentWorkflow(eventID, err)
	}
	event.Context = evidenceContext
	reply, err := s.LLM.Chat(ctx, autoAnalysisSystemPrompt, autoAnalysisPrompt(event, s.AssetMatchContext(event)))
	if err != nil {
		err = fmt.Errorf("LLM自动分析失败，请检查LLM配置: %w", err)
		_ = s.addLLMConfigRequiredMessage(eventID, roundID, err.Error())
		// 同上：保持 pending（列表显示未分析），等 LLM 恢复后自动重试。
		_, _ = s.Store.UpdateEvent(eventID, map[string]any{"event_status": "pending"})
		realtime.BroadcastStatus(eventID, map[string]any{"event_id": eventID, "status": "llm_config_required", "message": err.Error()})
		return err
	}

	sm, err := s.Store.AddSummary(domain.Summary{
		EventID:      eventID,
		RoundID:      roundID,
		EventSummary: reply,
		Version:      version,
		Kind:         kind,
	})
	if err != nil {
		return s.failAgentWorkflow(eventID, fmt.Errorf("保存分析总结失败: %w", err))
	}
	// 专家消息写库失败必须让状态如实反映：吞掉错误仍标记 round_finished 会出现
	// “列表显示已生成、报告里却只有创建事件”的假完成状态。
	if err := s.addAgentMessage(eventID, domain.RoleExpert, "event_summary", roundID,
		llmExpertResponse(event, roundID, sm, reply)); err != nil {
		return s.failAgentWorkflow(eventID, fmt.Errorf("保存专家分析消息失败: %w", err))
	}
	if err := s.MarkReportSnapshot(ctx, eventID, event.Context); err != nil {
		return s.failAgentWorkflow(eventID, err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	patch := map[string]any{
		"event_status":     "round_finished",
		"analysis_version": version,
		"last_analysis_at": now,
	}
	// 提取模型输出的威胁概率并入事件 context 持久化（ai_probability，0-100），
	// 供列表「研判概率」列展示与排序。注意合并进存储 context 而非 event.Context
	// （后者是 EvidenceContext 生成的模型输入精简版，不含 src_ip 等入库字段）。
	// 提取失败不写：保留历史值，且与 0% 区分「未研判」。
	if probability, ok := parseThreatProbability(reply); ok {
		if stored, found := s.Store.GetEvent(eventID); found {
			ctxMap := decodeEventContext(stored.Context)
			ctxMap["ai_probability"] = probability
			if raw, err := json.Marshal(ctxMap); err == nil {
				patch["context"] = string(raw)
			}
		}
	}
	_, _ = s.Store.UpdateEvent(eventID, patch)
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
const autoAnalysisSystemPrompt = `你是 DeepSOC 安全运营自动分析引擎。仅基于给定的安全事件信息研判，不得编造未提供的日志、资产或情报事实。输出简体中文 Markdown。涉及证据附件/证据文件时只引用文件名，不得输出任何本地路径或下载路径。
统计量由系统计算；结合时间、协议、请求响应和不同证据之间的关联进行深入研判。全报告只使用一个概率指标：威胁事件概率（0–100%，即该事件是真实威胁的可信度），在开头【结论】与结尾结论各给出一次，两处数值必须一致。关键证据按 1、2、3 数字编号，以样本编号（sample_no）或时间+五元组+特征定位证据，报告禁止输出 hit_id/evidence_id 等哈希标识串。不得把模型样本称为全部原始明细；遵守 input_manifest 的扫描范围与缺失说明。没有证据支持的事实不写为确定结论。建议不写成已执行处置；未提供实际功能链接或执行记录时，标注“暂未实现”。最终结论面向安全团队，不输出面向模型的内部约束措辞，不使用“自动驾驶”。
报告以被攻击资产为论述主线：概览与结论必须点名被攻击资产，影响与建议围绕该资产展开。关键证据必须落到“证据→威胁特征”的对应关系（符合即指出符合哪类威胁特征，不符合则说明排除依据）。论述简明扼要：每个章节只承担自己的职责，同一判断不在多个章节重复展开。研判流程固定为三步：先定性威胁类型（具体网络攻击类型，如 C2 通信/botnet/phishing/DNS 隧道/端口扫描/挖矿/数据外传等；证据不支持攻击时定性为误报或正常业务），再逐条列出符合该攻击类型的证据并标注权重（高/中/低），最后给出威胁事件概率。只写有证据支撑的确定内容：没有证据支撑的判断不写进正文，移入信息缺口；正文禁止出现“可能/疑似/或许/大概”等模糊词。`

func autoAnalysisPrompt(event domain.Event, assetSection string) string {
	obsStr := formatObservables(event.Observables)
	auxStr := formatAuxContext(event.Context)
	if strings.TrimSpace(assetSection) == "" {
		assetSection = "无登记信息"
	}

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

## 资产清单匹配（系统权威资产库）
%s

# 分析要求
结合上方证据完成研判：威胁真假（是否误报）、攻击手法定性、影响面与横向风险、处置建议。
- IOC 语义铁律：命中情报 IOC 的一侧永远是威胁侧，另一端永远是被攻击资产；可观察对象 role=threat_source/affected_asset 已按此标注，直接采用，不得互换，禁止把 IOC 写成被攻击资产；
- 被攻击资产若命中「资产清单匹配」，必须写“资产名（地址）”，资产角色以清单登记为准，禁止只写裸 IP 或臆测角色；未命中则写“未登记（地址）”；
- 威胁侧命中资产清单中的登记资产（尤其 DNS/基础服务）时，先按清单身份复核方向与 DNS 语义再定性，禁止未经复核直接断言其为攻击发起方；
- role=source/destination 只是报文原始方向，不代表攻击发起方；direction/通联方向未知时不得断言谁发起攻击，写“方向待研判”；
- 利用「通联方向」（to_ioc=数据外传、from_ioc=载荷下载）与流量体量判断外传/下载/beacon；
- local_hit_count 仅为节点近似分诊提示，权威全局频次以 occurrence_count 为准，勿重复计数；
- 若事件带「建议处置(情报侧)」，需明确采纳或修正并说明理由；
- 信息不足时写清缺口与下一步应查询的数据；不要把未执行的剧本结果写成已完成。

# 输出格式（严格遵守）
第一行必须输出以【结论】开头的一句话总结，先给结论再展开；禁止复述输入信息、禁止第一人称思考过程、禁止输出模板外内容。
简明要求：事实字段只在事件概览表格出现一次；【结论】给出的定性后文只摆依据、不再重复下结论；各章节内容不交叉重复；证据编号与结论互相引用，不重复粘贴内容；最终结论压缩为决策要点，不复制前文段落。

【结论】<一句话：威胁类型定性(C2通信/botnet/phishing/DNS隧道等具体攻击类型，或误报/正常业务) + 威胁事件概率X%% + 被攻击资产 + 核心依据 + 建议动作>

## 事件概览
（用表格概括：事件ID、事件类型、检测方式、严重程度、当前状态、时间窗口、攻击源、被攻击资产、协议/端口、命中特征；被攻击资产必须单独一行并标注资产角色(如内网终端/服务器/DNS客户端，未知则写“未知”)）
## 关键证据
（按 1、2、3 编号，以 sample_no/时间+特征定位证据，禁止出现哈希标识串；每条格式：证据要点 → 符合/不符合哪类威胁特征 → 权重（高/中/低），如“样本3：固定周期间隔 60s 小包通讯 → 符合 C2 beacon 心跳特征 → 权重高”；覆盖行为异常、协议/指纹、心跳周期性、情报命中、成功性证据、排除性证据中实际存在的类别；无成功性证据时必须明确写“无成功性证据”）
## 攻击源与受影响资产分析
（以被攻击资产为中心：资产角色与重要性、暴露面、受影响程度与后续排查重点；攻击源性质与情报可信度；横向风险只写一段）
## 攻击链与风险判断
（三段式：威胁类型定性（具体攻击类型，如 C2 通信/botnet/phishing/DNS 隧道等，一句话明确不含糊）→ 攻击链阶段定位与证据权重汇总（引用关键证据编号及权重，不重复粘贴证据内容）→ 威胁事件概率0–100%%及依据（全报告唯一概率指标，与【结论】数值一致）；没有成功性证据不得声称攻击成功，证据不足的判断不写，移入信息缺口）
## 已执行处置/自动驾驶进展
（仅列系统有记录的任务/动作/执行结果；无记录写“暂无”；建议不得写成已执行）
## 后续处置建议
（围绕被攻击资产给出可执行的查询与验证步骤，每条一句话；系统未实现的能力标注“暂未实现”）
## 信息缺口
（每条缺口一行：为什么要查、由谁查询、查到后能改变什么判断）
## 可交付给安全团队的结论
（3–5 条决策要点，每条一行：威胁类型定性与威胁事件概率（与开头【结论】一致）、被攻击资产及当前状态、应立即执行的动作、后续观察项；不重复前文详细论述）`,
		event.EventID,
		firstNonEmpty(event.EventName, event.Title, "未命名事件"),
		firstNonEmpty(event.Severity, "unknown"),
		firstNonEmpty(event.Source, "unknown"),
		firstNonEmpty(event.Message, "无"),
		obsStr,
		auxStr,
		assetSection,
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

	if _, ok := ctx["snapshot_version"]; ok {
		// 注入前脱敏证据内部标识（68 位哈希），避免模型把无意义长串抄进报告。
		b, _ := json.Marshal(sanitizeEvidenceForPrompt(ctx))
		return "- 证据说明：hit_id 等内部标识已脱敏，命中样本按 sample_no 编号；引用证据用样本N/时间/特征，禁止输出哈希标识串。\n" + string(b)
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
			emit("", "通联方向", "to_ioc（数据流向 IOC，外传/上传特征）")
		case "from_ioc":
			emit("", "通联方向", "from_ioc（数据来自 IOC，下载特征）")
		default:
			emit("", "通联方向", fs["volume_role"])
		}
	}

	// 量化统计（聚合）：次数/窗口/速率/体量/规则/IOC/突发窗口。
	// 数字由确定性引擎计算，LLM 只基于这些数字做定性研判，不得修改或编造。
	if qs, ok := ctx[quantStatsKey].(map[string]any); ok && len(qs) > 0 {
		if line := formatQuantStats(qs); line != "" {
			b.WriteString("- 量化统计（聚合，数字为权威依据）：\n")
			for _, l := range strings.Split(line, "\n") {
				if strings.TrimSpace(l) != "" {
					b.WriteString("  " + l + "\n")
				}
			}
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
	// 只展示文件名，避免把节点上的完整 PCAP 路径带进分析上下文/报告。
	emit("", "证据文件", filepath.Base(scalarString(ctx["evidence_file"])))
	if efs, ok := ctx["evidence_files"].([]any); ok && len(efs) > 0 {
		b.WriteString("- 证据附件(evidence_files)：\n")
		for i, raw := range efs {
			ef, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name := scalarString(ef["name"])
			if name == "" {
				name = fmt.Sprintf("证据%d", i+1)
			}
			parts := []string{}
			if t := scalarString(ef["type"]); t != "" {
				parts = append(parts, "type="+t)
			}
			if size := scalarString(ef["size"]); size != "" && size != "0" {
				parts = append(parts, "size="+size)
			}
			b.WriteString("  - " + name)
			if len(parts) > 0 {
				b.WriteString("（" + strings.Join(parts, ", ") + "）")
			}
			b.WriteString("\n")
		}
	}
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
		"snapshot_version": decodeEventContext(event.Context)["snapshot_version"],
		"input_manifest":   decodeEventContext(event.Context)["input_manifest"],
		"type":             "llm_response",
		"from":             domain.RoleExpert,
		"to":               []string{domain.RoleCaptain},
		"event_id":         event.EventID,
		"round_id":         roundID,
		"response_type":    "SUMMARY",
		"response_text":    reply,
		"suggestions":      []string{},
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

// promptInternalIDKeys 注入 LLM 前需脱敏的证据内部标识字段：
// 68 位哈希对研判没有信息量，模型抄进报告只会稀释关键证据的可读性。
var promptInternalIDKeys = map[string]bool{
	"hit_id":          true,
	"evidence_id":     true,
	"origin_event_id": true,
	"dedup_key":       true,
	"identity_digest": true,
	"aggregate_key":   true,
}

// sanitizeEvidenceForPrompt 递归清理注入 prompt 的 context：
// 删除 hit_id/evidence_id 等内部标识；原含 hit_id 的样本条目按数组顺序补
// sample_no（从 1 起），供模型以“样本N”定位证据。
func sanitizeEvidenceForPrompt(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if promptInternalIDKeys[k] || k == "selected_hit_ids" {
				delete(t, k)
				continue
			}
			t[k] = sanitizeEvidenceForPrompt(val)
		}
		return t
	case []any:
		for i, item := range t {
			m, isMap := item.(map[string]any)
			_, hadHitID := m["hit_id"]
			item = sanitizeEvidenceForPrompt(item)
			if isMap && hadHitID {
				if mm, ok := item.(map[string]any); ok {
					mm["sample_no"] = i + 1
				}
			}
			t[i] = item
		}
		return t
	default:
		return v
	}
}
