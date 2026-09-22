package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

// aggregateIdleWindow 聚合收敛窗口：距最近一次命中超过该时长无新增，即判定已收敛，
// 此刻的发生次数视为该聚合事件的“最终频次”。与 internal/service 的
// ConvergenceIdleWindow 保持一致（量化终报依赖同一窗口）。
const aggregateIdleWindow = trafficservice.ConvergenceIdleWindow

func eventVolumeQuality(ctx map[string]any) string {
	if qs, ok := ctx["quant_stats"].(map[string]any); ok {
		return firstNonEmpty(stringValue(qs["volume_quality"]), "unverified")
	}
	return "unverified"
}

func quantPayloadDisplay(ctx map[string]any) any {
	if qs, ok := ctx["quant_stats"].(map[string]any); ok && qs["volume_quality"] == "unverified" {
		return nil
	}
	return quantPayloadBytes(ctx)
}

type EventService struct {
	core trafficservice.Services
}

func NewEventService(core trafficservice.Services) *EventService {
	return &EventService{core: core}
}

func (s *EventService) Create(ctx context.Context, body map[string]any) (domain.Event, error) {
	created, err := s.core.CreateEventFromRequest(body)
	if err != nil {
		return domain.Event{}, err
	}
	// 分析必须异步且脱离请求上下文：同步跑会让创建接口阻塞到 LLM 返回，
	// 前端超时断开即取消请求 ctx，报告页会留下“Post ... context canceled”
	// 的假故障消息；Async 内部用 Background ctx 并带同事件去重锁。
	s.core.RunAgentWorkflowAsync(created.EventID)
	return created, nil
}

func (s *EventService) List(ctx context.Context) []domain.Event {
	return s.core.Store.ListEvents()
}

func (s *EventService) LyCompatibleList(ctx context.Context) []map[string]any {
	events := s.core.Store.ListEvents()
	rows := make([]map[string]any, 0, len(events))
	for _, event := range events {
		rows = append(rows, lyCompatibleEvent(event))
	}
	return rows
}

// ListPage 服务端分页/过滤的事件列表（LY 兼容结构），供今日/归档视图与全局搜索使用。
func (s *EventService) ListPage(ctx context.Context, q store.EventQuery) ([]map[string]any, int, error) {
	page, err := s.core.Store.ListEventsPage(q)
	if err != nil {
		return nil, 0, err
	}
	rows := make([]map[string]any, 0, len(page.Items))
	for _, event := range page.Items {
		rows = append(rows, lyCompatibleEvent(event))
	}
	return rows, page.Total, nil
}

// GetArchiveJob 查询每日归档任务状态。
func (s *EventService) GetArchiveJob(jobID string) (domain.ArchiveJob, bool) {
	return s.core.Store.GetArchiveJob(jobID)
}

func (s *EventService) Detail(ctx context.Context, eventID string) (domain.Event, bool) {
	return s.core.Store.GetEvent(eventID)
}

func (s *EventService) Occurrences(ctx context.Context, eventID, cursor, hitID string, limit int, version int64, timeRange ...string) (trafficservice.OccurrencePage, error) {
	return s.core.OccurrencesAt(ctx, eventID, cursor, hitID, limit, version, timeRange...)
}

func (s *EventService) Messages(ctx context.Context, eventID string) []domain.Message {
	return s.core.Store.ListMessages(eventID)
}

func (s *EventService) Tasks(ctx context.Context, eventID string) []domain.Task {
	return s.core.Store.ListTasks(eventID)
}

func (s *EventService) Actions(ctx context.Context, eventID string) []domain.Action {
	return s.core.Store.ListActions(eventID)
}

func (s *EventService) Commands(ctx context.Context, eventID string) []domain.Command {
	return s.core.Store.ListCommands(eventID)
}

func (s *EventService) Stats(ctx context.Context, eventID string) map[string]any {
	out := map[string]any{
		"event_id":     eventID,
		"messages":     len(s.core.Store.ListMessages(eventID)),
		"tasks":        len(s.core.Store.ListTasks(eventID)),
		"actions":      len(s.core.Store.ListActions(eventID)),
		"commands":     len(s.core.Store.ListCommands(eventID)),
		"executions":   len(s.core.Store.ListExecutions(eventID)),
		"summaries":    len(s.core.Store.ListSummaries(eventID)),
		"generated_at": time.Now().UTC(),
	}
	if event, ok := s.core.Store.GetEvent(eventID); ok {
		var c map[string]any
		_ = json.Unmarshal([]byte(event.Context), &c)
		for _, k := range []string{"occurrence_count", "quant_stats", "stats_version", "data_version", "statistics_quality"} {
			out[k] = c[k]
		}
		if version, _ := strconv.ParseInt(stringValue(c["stats_version"]), 10, 64); version > 0 {
			if snap, err := s.core.EvidenceSnapshot(ctx, eventID, version); err == nil {
				out["quant_stats"] = snap.Context["quant_stats"]
			} else {
				out["quant_stats"] = nil
				out["statistics_error"] = err.Error()
			}
		}
	}
	return out
}

func (s *EventService) Summaries(ctx context.Context, eventID string) []domain.Summary {
	return s.core.Store.ListSummaries(eventID)
}

// RefreshReport 手动刷新事件分析报告：后台异步执行（脱离请求上下文），
// 立即返回当前版本与状态，避免请求超时中断 LLM 调用。
func (s *EventService) RefreshReport(ctx context.Context, eventID string) (map[string]any, error) {
	ev, ok := s.core.Store.GetEvent(eventID)
	if !ok {
		return nil, errors.New("事件不存在")
	}
	status := "refresh_submitted"
	if !s.core.RefreshAnalysisAsync(eventID) {
		status = "already_running"
	}
	return map[string]any{
		"event_id":         eventID,
		"analysis_version": ev.AnalysisVersion,
		"status":           status,
	}, nil
}

func (s *EventService) SendMessage(ctx context.Context, eventID string, body map[string]any) (domain.Message, error) {
	if _, ok := s.core.Store.GetEvent(eventID); !ok {
		return domain.Message{}, errors.New("事件不存在")
	}
	content := firstString(body, "message", "message_content")
	if content == "" {
		return domain.Message{}, errors.New("消息内容不能为空")
	}
	msg := domain.Message{
		EventID:         eventID,
		UserID:          stringValue(body["user_id"]),
		UserNickname:    stringValue(body["user_nickname"]),
		MessageFrom:     trafficservice.NormalizeMessageFrom(firstString(body, "message_from", "sender", "user")),
		MessageType:     firstString(body, "message_type", "user_message"),
		MessageContent:  content,
		RoundID:         1,
		MessageCategory: "agent",
	}
	msg.SenderType = trafficservice.SenderType(msg.MessageFrom)
	return s.core.Store.AddMessage(msg)
}

func (s *EventService) Executions(ctx context.Context, eventID string) []domain.Execution {
	return s.core.Store.ListExecutions(eventID)
}

func (s *EventService) CompleteExecution(ctx context.Context, executionID string) map[string]string {
	return map[string]string{"execution_id": executionID}
}

func (s *EventService) Hierarchy(ctx context.Context, eventID string) map[string]any {
	return map[string]any{
		"event_id":   eventID,
		"messages":   s.core.Store.ListMessages(eventID),
		"tasks":      s.core.Store.ListTasks(eventID),
		"actions":    s.core.Store.ListActions(eventID),
		"commands":   s.core.Store.ListCommands(eventID),
		"executions": s.core.Store.ListExecutions(eventID),
		"summaries":  s.core.Store.ListSummaries(eventID),
	}
}

func lyCompatibleEvent(event domain.Event) map[string]any {
	context := map[string]any{}
	if event.Context != "" {
		_ = json.Unmarshal([]byte(event.Context), &context)
	}

	source, destination := observablePair(event.Observables)
	source = firstNonEmpty(source, stringValue(context["threat_source"]), stringValue(context["src_ip"]))
	destination = firstNonEmpty(destination, stringValue(context["victim_target"]), stringValue(context["dst_ip"]))
	// Preserve the original packet direction for correlation and AI analysis.
	srcIP, dstIP := source, destination
	// Keep the packet IPs below for correlation, but display the hostname when
	// ta_node captured one. Native IP traffic therefore remains IP-only.
	domainName := eventDomain(context)
	indicator := threatIndicator(context)
	if _, client := dnsResolutionPeers(context); client != "" {
		// DNS 解析流量：威胁侧是域名（IOC 或 dns_query），受害侧是发起查询的
		// 内网主机；公共 DNS（如 218.2.2.2）不出现在受害列。
		// src_ip/dst_ip 保持原始报文方向，供研判重推/AI 分析使用。
		if threat := firstNonEmpty(indicator, domainName); threat != "" {
			source, destination = threat, client
			domainName = threat
		} else {
			// 无域名信息时无法归属威胁侧：置空攻击列，避免把公共 DNS 服务器
			// （应答方向）或内网主机自身（查询方向）误标为攻击源。
			source, destination = "", client
		}
	} else {
		if indicator != "" {
			// A domain/URL IOC is the threat source being accessed. Keep the
			// protected host as the displayed destination, while src_ip/dst_ip
			// below remain the original packet direction.
			source, destination = indicator, source
			domainName = indicator
		}
		// 原始流向不随 IOC 展示修正交换。
		// IOC 规则地址修正：IP/CIDR 型 IOC 命中且目的地址即 IOC 值时，目的地址是威胁地址
		// （如 C2），并非受害主机；交换展示源/目标，使「受害目标」列不出现 IOC 规则 IP。
		if iocDestinationIsIOC(context, destination) {
			source, destination = destination, source
		}
		if domainName != "" && indicator == "" {
			destination = domainName
		}
	}
	eventType := firstNonEmpty(stringValue(context["event_type"]), stringValue(context["type"]), "cap")
	level := lyLevel(event.Severity)
	first := domain.ParseEventTime(context["first_time"])
	if first.IsZero() {
		first = domain.ParseEventTime(context["occurrence_time"])
	}
	if first.IsZero() {
		first = event.CreatedAt
	}
	lastSeen := domain.LastActivity(event)
	now := time.Now().UTC()
	isFinal := domain.IsConverged(event, now)
	aggregationStatus := "active"
	var convergedAt any
	end := now
	if isFinal {
		aggregationStatus = "closed"
		// The quiet window is a detection delay, not part of the attack duration.
		convergedAt = lastSeen.In(domain.Beijing).Format(time.RFC3339Nano)
		end = lastSeen
	}
	duration := int64(end.Sub(first).Seconds())
	if duration < 0 {
		duration = 0
	}
	startTime := first.Unix()
	analysisStatus := analysisStatusForEvent(event.EventStatus)
	// 聚合快照基于全量命中计算的心跳结论优先；旧数据（无快照字段）回退到
	// 用 context 里的 occurrences（可能仅是最近 10 条 UI 预览）本地判定。
	heartbeat, heartbeatPeriod, persisted := persistedHeartbeat(context)
	if !persisted {
		heartbeat, heartbeatPeriod = detectHeartbeat(context["occurrences"])
	}
	// 心跳（固定周期的小包通信）是 C2 信标的强特征：命中时展示等级提升一档
	// （low→middle→high），high/critical 不再上调；原始级别保留在 level_raw 供审计。
	levelBoosted := false
	if heartbeat {
		if boosted := heartbeatBoostedLevel(level); boosted != level {
			level, levelBoosted = boosted, true
		}
	}
	// 多域名聚合标注：采样命中明细里的去重查询域名，供列表避免单域名误导。
	dnsQueries, dnsDomainCount := dnsQuerySet(context)

	return map[string]any{
		"id":           firstNonEmpty(event.EventID, stringValue(event.ID)),
		"event_id":     event.EventID,
		"attackDevice": source,
		"victimDevice": destination,
		"obj":          source + ">" + destination,
		// 原始流向（不随 IOC 修正交换）：研判重推/AI 分析使用，保证指纹稳定。
		"src_ip":               srcIP,
		"dst_ip":               dstIP,
		"domain":               domainName,
		"heartbeat_detected":   heartbeat,
		"heartbeat_period_sec": heartbeatPeriod,
		"heartbeat_level_boost": levelBoosted,
		"level_raw":             lyLevel(event.Severity),
		"dns_queries":           dnsQueries,
		"dns_domain_count":      dnsDomainCount,
		// 事件总载荷（字节）：quant_stats.total_payload_bytes，列表「总载荷」列与排序口径。
		"total_payload_bytes": quantPayloadDisplay(context),
		"type":                eventType,
		"level":               level,
		// 原始威胁等级（high/medium/low）：level 是展示级（medium→middle，且可能被心跳提升），
		// 前端级别筛选须按本字段，避免中/低危被展示级误杀。
		"severity":            event.Severity,
		"desc":                firstNonEmpty(event.EventName, event.Title, event.Message),
		"rule_desc":           firstNonEmpty(event.EventName, event.Title, event.Message),
		"proc_status":         "unprocessed",
		"processing_status":   "unprocessed",
		"analysis_status":     analysisStatus,
		"analysisStatus":      analysisStatus,
		"starttime":           startTime,
		"time":                startTime,
		"duration":            duration,
		"converged_at":        convergedAt,
		"last_seen_at":        lastSeen.In(domain.Beijing).Format(time.RFC3339Nano),
		"timezone":            "Asia/Shanghai",
		"is_alive":            !isFinal,
		"is_active":           !isFinal,
		"show_model":          firstNonEmpty(stringValue(context["detection_method"]), stringValue(context["protocol"])),
		"source":              event.Source,
		// 聚合信息：发生次数与首/末次时间（同来源+目标+类型、仅时间不同的事件已合并为一条）
		"event_count":         context["occurrence_count"],
		"aggregation_version": context["aggregation_version"],
		"data_version":        context["data_version"],
		"stats_version":       context["stats_version"],
		"statistics_quality":  firstNonEmpty(stringValue(context["statistics_quality"]), "unverified"),
		"volume_quality":      eventVolumeQuality(context),
		"canonical_event_id":  context["canonical_event_id"],
		"report_stale":        context["report_stale"],
		"occurrences_total":   context["occurrences_total"],
		"occurrences_preview": context["occurrences_preview"],
		"first_time":          first.In(domain.Beijing).Format(time.RFC3339Nano),
		"last_time":           lastSeen.In(domain.Beijing).Format(time.RFC3339Nano),
		// 收敛状态：active=进行中(可能继续)，closed=已收敛(occurrence_count 即最终频次)
		"aggregation_status": aggregationStatus,
		"is_final":           isFinal,
		// 每次命中明细：时间 + 数据包大小(wire_bytes) + 包数(packets)，供前端命中频次弹窗
		"occurrences": context["occurrences"],
		// 事件级扩展字段：会话统计、流量统计、情报元数据
		"session_summary":    context["session_summary"],
		"flow_stats":         context["flow_stats"],
		"ioc":                context["ioc"],
		"ioc_evidence":       context["ioc_evidence"],
		"recommended_action": context["recommended_action"],
		"evidence_files":     context["evidence_files"],
		// 审核状态：供事件列表展示「待审核/已通过/已驳回」与通报编号
		"review_status": event.ReviewStatus,
		"circular_code": event.CircularCode,
		// 量化分析版本与收敛状态（供前端展示初版/终版/手动刷新）。
		"analysis_version":   event.AnalysisVersion,
		"aggregation_closed": isFinal,
		"last_analysis_at":   event.LastAnalysisAt,
		"archive_date":       event.ArchiveDate,
	}
}

// eventDomain extracts the best hostname evidence supplied by ta_node.
func eventDomain(ctx map[string]any) string {
	if app, ok := ctx["app"].(map[string]any); ok {
		if v := firstNonEmpty(stringValue(app["http_host"]), stringValue(app["dns_query"]), stringValue(app["tls_sni"])); v != "" {
			return v
		}
	}
	if ioc, ok := ctx["ioc"].(map[string]any); ok && (strings.EqualFold(stringValue(ioc["ioc_type"]), "domain") || strings.EqualFold(stringValue(ioc["ioc_type"]), "url")) {
		return stringValue(ioc["ioc_value"])
	}
	return ""
}

// dnsQuerySet 汇总事件已采样命中明细里的去重查询域名：v1 读 context.occurrences
// （buildOccurrence 存平铺 dns_query），v2 读 context.occurrences_preview
// （previewOccurrence 保留嵌套 app.dns_query）。聚合事件的 128 次命中可能查询
// 多个不同域名（如停放域名都解析到 127.0.0.1），列表仅凭首条命中的单域名展示
// 会误导研判。返回去重列表（最多 10 个）与采样内去重总数。
func dnsQuerySet(ctx map[string]any) (queries []string, total int) {
	seen := map[string]bool{}
	add := func(q string) {
		q = strings.TrimSpace(q)
		if q == "" || seen[q] {
			return
		}
		seen[q] = true
		total++
		if len(queries) < 10 {
			queries = append(queries, q)
		}
	}
	for _, raw := range []any{ctx["occurrences"], ctx["occurrences_preview"]} {
		items, _ := raw.([]any)
		for _, item := range items {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			add(stringValue(m["dns_query"]))
			if app, ok := m["app"].(map[string]any); ok {
				add(stringValue(app["dns_query"]))
			}
		}
	}
	return queries, total
}

// dnsResolutionPeers 识别 DNS 解析流量，返回 (server, client)。
// 端口优先：dst_port=53 为查询方向、src_port=53 为应答方向；
// 端口缺失时要求存在 app.dns_query，并用内网地址兜底判定客户端。
// 无法可靠判定（双内网/双外网、无端口且无域名）时返回空，展示保持原样。
func dnsResolutionPeers(ctx map[string]any) (server, client string) {
	src := stringValue(ctx["src_ip"])
	dst := stringValue(ctx["dst_ip"])
	switch {
	case numberValue(ctx["dst_port"]) == 53:
		return dst, src
	case numberValue(ctx["src_port"]) == 53:
		return src, dst
	}
	app, _ := ctx["app"].(map[string]any)
	if stringValue(app["dns_query"]) == "" {
		return "", ""
	}
	srcPrivate, dstPrivate := false, false
	if ip, err := netip.ParseAddr(src); err == nil {
		srcPrivate = ip.Unmap().IsPrivate()
	}
	if ip, err := netip.ParseAddr(dst); err == nil {
		dstPrivate = ip.Unmap().IsPrivate()
	}
	// 仅当恰好一侧为内网地址时才可可靠判定客户端；双内网/双外网不干预。
	switch {
	case srcPrivate && !dstPrivate:
		return dst, src
	case dstPrivate && !srcPrivate:
		return src, dst
	}
	return "", ""
}
func threatIndicator(ctx map[string]any) string {
	ioc, ok := ctx["ioc"].(map[string]any)
	if !ok {
		return ""
	}
	typ := strings.ToLower(strings.TrimSpace(stringValue(ioc["ioc_type"])))
	if typ != "domain" && typ != "url" {
		return ""
	}
	return stringValue(ioc["ioc_value"])
}

// persistedHeartbeat 读取聚合快照在全量命中上预计算的心跳结论。
// 第三个返回值表示快照结论是否存在（false 也是有效结论，不能用零值判断）。
func persistedHeartbeat(context map[string]any) (bool, int64, bool) {
	detected, ok := context["heartbeat_detected"].(bool)
	if !ok {
		return false, 0, false
	}
	return detected, int64(numberValue(context["heartbeat_period_sec"])), true
}

// detectHeartbeat 把 context["occurrences"] 明细转为观测并委托 domain 判定；
// 仅作为无快照心跳结论时的回退路径。
func detectHeartbeat(raw any) (bool, int64) {
	items, ok := raw.([]any)
	if !ok || len(items) < 8 {
		return false, 0
	}
	obs := make([]domain.HeartbeatObservation, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		obs = append(obs, domain.HeartbeatObservation{
			At:      domain.ParseEventTime(stringValue(m["time"])),
			Packets: numberValue(m["packets"]),
		})
	}
	return domain.DetectHeartbeat(obs)
}

func numberValue(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case uint64:
		return float64(x)
	case string:
		// 兼容上游以字符串形式传端口/计数（如 "53"）。
		if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
			return f
		}
	}
	return 0
}

func analysisStatusForEvent(status string) string {
	switch status {
	case "round_finished":
		return "completed"
	case "processing":
		return "processing"
	case "llm_config_required":
		return "llm_config_required"
	case "failed":
		return "failed"
	default:
		return "pending"
	}
}

func observablePair(items []domain.IOC) (string, string) {
	var source, destination string
	for _, item := range items {
		switch item.Role {
		case "source":
			source = item.Value
		case "destination":
			destination = item.Value
		}
	}
	return source, destination
}

// iocDestinationIsIOC 判定展示目标地址是否为 IP/CIDR 型 IOC 规则地址。
// ioc_type ∈ {ip, cidr} 且 destination 命中 ioc_value（cidr 按网段包含匹配）时返回 true。
func iocDestinationIsIOC(ctx map[string]any, destination string) bool {
	ioc, _ := ctx["ioc"].(map[string]any)
	iocType := strings.ToLower(strings.TrimSpace(stringValue(ioc["ioc_type"])))
	iocValue := strings.TrimSpace(stringValue(ioc["ioc_value"]))
	if iocType == "" || iocValue == "" || strings.TrimSpace(destination) == "" {
		return false
	}
	dst := strings.ToLower(strings.TrimSpace(destination))
	switch iocType {
	case "ip":
		return dst == strings.ToLower(iocValue)
	case "cidr":
		if network, err := netip.ParsePrefix(strings.ToLower(iocValue)); err == nil {
			if addr, err := netip.ParseAddr(dst); err == nil {
				return network.Contains(addr)
			}
		}
		return false
	default:
		return false
	}
}

// quantPayloadBytes 读取 context.quant_stats.total_payload_bytes（旧事件缺失返回 0）。
func quantPayloadBytes(ctx map[string]any) int64 {
	qs, _ := ctx["quant_stats"].(map[string]any)
	if qs == nil {
		return 0
	}
	switch v := qs["total_payload_bytes"].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func lyLevel(severity string) string {
	switch severity {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "middle"
	case "low":
		return "low"
	default:
		return "middle"
	}
}

// heartbeatBoostedLevel 心跳命中时的展示等级提升：low→middle→high，
// high/critical 不再上调。
func heartbeatBoostedLevel(level string) string {
	switch level {
	case "low":
		return "middle"
	case "middle":
		return "high"
	default:
		return level
	}
}

func unixLike(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	case string:
		if t, err := time.Parse(time.RFC3339, x); err == nil {
			return t.Unix(), true
		}
	}
	return 0, false
}

// Review 处理人工审核；approve 时把事件推送到通报处置并记录 circular_code。
// 仅 event_status == "round_finished" 的事件可审核。bearer/fallbackBase 透传给 CircularClient。
func (s *EventService) Review(ctx context.Context, eventID, action, comment, reviewedBy, bearer, fallbackBase string) (map[string]any, error) {
	event, ok := s.core.Store.GetEvent(eventID)
	if !ok {
		return nil, errors.New("事件不存在")
	}
	if event.EventStatus != "round_finished" {
		return nil, errors.New("仅 AI 分析完成的事件可审核")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	switch action {
	case "reject":
		s.core.Store.UpdateEvent(eventID, map[string]any{
			"review_status":  "rejected",
			"review_comment": comment,
			"reviewed_by":    reviewedBy,
			"reviewed_at":    now,
		})
		return map[string]any{"review_status": "rejected"}, nil

	case "approve":
		// 幂等：已推送过则直接返回既有编号
		if event.CircularCode != "" {
			return map[string]any{"review_status": "approved", "circular_code": event.CircularCode}, nil
		}
		req := buildTransferIncidentReq(event, s.core.Store.ListSummaries(eventID))
		code, err := s.core.Circular.ReceiveIncident(ctx, req, bearer, fallbackBase)
		if err != nil {
			return nil, err
		}
		s.core.Store.UpdateEvent(eventID, map[string]any{
			"review_status":  "approved",
			"review_comment": comment,
			"reviewed_by":    reviewedBy,
			"reviewed_at":    now,
			"circular_code":  code,
		})
		return map[string]any{"review_status": "approved", "circular_code": code}, nil

	default:
		return nil, errors.New("无效的审核动作")
	}
}
