package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/mq"
	"vulnscan-backend/traffic/internal/store"
)

// maxOccurrences 限制单条聚合事件保留的发生时间数量，避免 context 无限膨胀。
const maxOccurrences = 200

type Services struct {
	Store      store.Store
	DeepSOC    client.DeepSOCClient
	FlowShadow client.FlowShadowClient
	Circular   client.CircularClient
	// LLM 为指针：Services 以值语义被复制进各子服务（EventService/InternalService/
	// SystemService 等），共享同一个 LLM 客户端，使配置页保存(SetLLMConfig)的 base_url/
	// api_key/model 能即时对”分析引擎”(RunAgentWorkflow)生效，无需重启。
	LLM   *client.LLMClient
	Queue mq.Queue
}

func (s Services) ProcessLyEvent(ctx context.Context, ly map[string]any) (map[string]any, error) {
	fp := Fingerprint(ly)
	lyID := asString(ly["id"])
	if !s.Store.ReserveFingerprint(fp) {
		row, _ := s.Store.GetEventMap(fp)
		// 研判请求（前端“查看报告”重推）只是复用既有事件，不能计为一次新命中，
		// 否则会虚增发生次数并重置收敛时钟，使“最终频次”失真。
		// 仍按需补跑一次分析（RunAgentWorkflow 幂等：已分析则跳过），
		// 保证“查看报告”能触发研判而不影响频次。
		if asBool(ly["analysis_only"]) {
			s.RunAgentWorkflowAsync(row.DeepSOCEventID)
			return map[string]any{
				"aggregated":       false,
				"reason":           "analysis-only",
				"fingerprint":      fp,
				"ly_id":            lyID,
				"deepsoc_event_id": row.DeepSOCEventID,
			}, nil
		}
		// 命中既有聚合键（同来源+目标+类型，仅时间不同）：合并到既有事件，
		// 累加发生次数、更新首/末次时间与发生时间列表，不重复触发分析。
		count := s.mergeOccurrence(row.DeepSOCEventID, ly)
		return map[string]any{
			"aggregated":       true,
			"reason":           "merged-by-aggregate-key",
			"fingerprint":      fp,
			"ly_id":            lyID,
			"deepsoc_event_id": row.DeepSOCEventID,
			"occurrence_count": count,
		}, nil
	}

	payload := LyEventToDeepSOC(ly)
	if s.DeepSOC.Enabled() {
		resp, err := s.DeepSOC.CreateEvent(ctx, payload, fp)
		if err != nil {
			return nil, err
		}
		deepID := extractEventID(resp)
		s.Store.BindEventMap(fp, lyID, deepID)
		_ = s.publish(ctx, "event.ingested", deepID, "flowshadow", map[string]any{
			"fingerprint": fp,
			"ly_event_id": lyID,
			"upstream":    resp,
		})
		return map[string]any{"success": true, "fingerprint": fp, "ly_event_id": lyID, "deepsoc_event_id": deepID, "upstream": resp}, nil
	}

	if payload.EventID == "" {
		payload.EventID = "ly-" + fp[:16]
	}
	event, err := s.Store.CreateEvent(payload)
	if err != nil {
		return nil, err
	}
	s.Store.BindEventMap(fp, lyID, event.EventID)
	_, _ = s.Store.AddMessage(domain.Message{
		EventID:         event.EventID,
		MessageFrom:     domain.RoleSystem,
		MessageType:     "system_notification",
		MessageContent:  StandardContent(responseText("系统创建了安全事件: "+firstNonEmpty(event.EventName, "未命名事件"), nil)),
		RoundID:         1,
		MessageCategory: "agent",
		SenderType:      "system",
	})
	_ = s.publish(ctx, "event.ingested", event.EventID, "flowshadow", map[string]any{
		"fingerprint": fp,
		"ly_event_id": lyID,
		"event":       event,
	})
	s.RunAgentWorkflowAsync(event.EventID)
	return map[string]any{"success": true, "fingerprint": fp, "ly_event_id": lyID, "deepsoc_event_id": event.EventID}, nil
}

// mergeOccurrence 把一条同聚合键的新事件合并进既有事件：累加发生次数、
// 更新首/末次时间与发生时间列表，并把聚合摘要写回 message。返回累计次数。
func (s Services) mergeOccurrence(eventID string, ly map[string]any) int {
	if eventID == "" {
		return 0
	}
	ev, ok := s.Store.GetEvent(eventID)
	if !ok {
		return 0
	}
	ctx := map[string]any{}
	if ev.Context != "" {
		_ = json.Unmarshal([]byte(ev.Context), &ctx)
	}

	count := toInt(ctx["occurrence_count"])
	if count < 1 {
		count = 1
	}
	count++
	ctx["occurrence_count"] = count

	occ := firstNonEmpty(asString(ly["occurrence_time"]), asString(ly["time"]))
	if occ != "" {
		first := asString(ctx["first_time"])
		last := asString(ctx["last_time"])
		if first == "" || occ < first {
			ctx["first_time"] = occ
		}
		if last == "" || occ > last {
			ctx["last_time"] = occ
		}
		occs, _ := ctx["occurrences"].([]any)
		occs = append(occs, buildOccurrence(ly))
		if len(occs) > maxOccurrences {
			occs = occs[len(occs)-maxOccurrences:]
		}
		ctx["occurrences"] = occs
	}
	// 聚合证据累积：后续命中的 PCAP 一并保留（按 path_ref/sha256 去重），
	// 供“下载全部 PCAP(ZIP)”取回聚合事件首末区间内的全部证据。
	if ef := normalizeEvidenceFiles(ly, count-1, occ); len(ef) > 0 {
		mergeEvidenceFiles(ctx, ef)
	}
	// 刷新服务器侧最近命中时刻，用于静默超时收敛判定
	lastSeenAt := time.Now().UTC()
	ctx["last_seen_at"] = lastSeenAt.Format(time.RFC3339)
	// 量化统计增量累计
	updateQuantStats(ctx, ly)

	ctxJSON, _ := json.Marshal(ctx)
	summary := fmt.Sprintf("%s（聚合 %d 次，首次 %s，末次 %s）",
		firstNonEmpty(ev.EventName, ev.Title, "安全事件"),
		count, asString(ctx["first_time"]), asString(ctx["last_time"]))
	s.Store.UpdateEvent(eventID, map[string]any{
		"context":      string(ctxJSON),
		"message":      summary,
		"last_seen_at": lastSeenAt.Format(time.RFC3339),
	})
	return count
}

func toInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	}
	return 0
}

func asBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1"
	}
	return false
}

func nestedMap(m map[string]any, key string) map[string]any {
	if v, ok := m[key]; ok {
		if nm, ok := v.(map[string]any); ok {
			return nm
		}
	}
	return nil
}

func (s Services) RunSyncOnce(ctx context.Context, batchSize, lookbackSeconds, maxRetries int) (map[string]any, error) {
	cursor := s.Store.GetCursor("flowshadow_events")
	since := cursor.LastTS
	if since == "" {
		since = time.Now().UTC().Add(-time.Duration(lookbackSeconds) * time.Second).Format(time.RFC3339)
	}
	items, err := s.FlowShadow.ListEvents(ctx, since, batchSize)
	if err != nil {
		return nil, err
	}

	pushed, failed := 0, 0
	newestTS := since
	for _, ev := range items {
		evTS := asString(ev["time"])
		if evTS != "" && evTS > newestTS {
			newestTS = evTS
		}
		recordID := asString(ev["event_id"])
		idemKey := MakeIdempotencyKey(ev)
		if recordID == "" {
			recordID = "noid:" + idemKey
		}
		if s.Store.AlreadyPushed(recordID) {
			continue
		}
		pe := domain.PushedEvent{LyEventID: recordID, IdempotencyKey: idemKey, Status: "FAILED"}
		var lastErr error
		for i := 0; i < maxRetries; i++ {
			pe.Attempts = i + 1
			res, err := s.ProcessLyEvent(ctx, ev)
			if err == nil {
				pe.Status = "SUCCESS"
				pe.DeepSOCEventID = asString(res["deepsoc_event_id"])
				lastErr = nil
				break
			}
			lastErr = err
		}
		if lastErr != nil {
			pe.LastError = lastErr.Error()
			failed++
		} else {
			pushed++
		}
		s.Store.SavePushedEvent(pe)
	}
	s.Store.SaveCursor(domain.SyncCursor{Name: "flowshadow_events", LastTS: newestTS})
	_ = s.publish(ctx, "sync.completed", "", "flowshadow", map[string]any{"since": since, "newest_ts": newestTS, "fetched": len(items), "pushed": pushed, "failed": failed})
	return map[string]any{"since": since, "newest_ts": newestTS, "fetched": len(items), "pushed": pushed, "failed": failed}, nil
}

func (s Services) CreateEventFromRequest(body map[string]any) (domain.Event, error) {
	msg := asString(body["message"])
	if msg == "" {
		return domain.Event{}, errors.New("事件消息不能为空")
	}
	eventID := asString(body["event_id"])
	if eventID == "" {
		eventID = newID("evt")
	}
	e := domain.Event{
		EventID:     eventID,
		EventName:   firstNonEmpty(asString(body["event_name"]), asString(body["title"])),
		Title:       asString(body["title"]),
		Message:     msg,
		Context:     asString(body["context"]),
		Source:      firstNonEmpty(asString(body["source"]), "manual"),
		Severity:    firstNonEmpty(asString(body["severity"]), "medium"),
		Category:    asString(body["category"]),
		EventStatus: "pending",
	}
	if obs, ok := body["observables"].([]any); ok {
		for _, item := range obs {
			if m, ok := item.(map[string]any); ok {
				e.Observables = append(e.Observables, domain.IOC{Type: asString(m["type"]), Value: asString(m["value"]), Role: asString(m["role"])})
			}
		}
	}
	created, err := s.Store.CreateEvent(e)
	if err != nil {
		return domain.Event{}, err
	}
	_, _ = s.Store.AddMessage(domain.Message{
		EventID:         created.EventID,
		MessageFrom:     domain.RoleSystem,
		MessageType:     "system_notification",
		MessageContent:  StandardContent(responseText("系统创建了安全事件: "+firstNonEmpty(created.EventName, "未命名事件"), nil)),
		RoundID:         1,
		MessageCategory: "agent",
		SenderType:      "system",
	})
	_ = s.publish(context.Background(), "event.created", created.EventID, firstNonEmpty(created.Source, "manual"), created)
	return created, nil
}

func (s Services) publish(ctx context.Context, routingKey, eventID, source string, payload interface{}) error {
	if s.Queue == nil || !s.Queue.Enabled() {
		return nil
	}
	return s.Queue.Publish(ctx, routingKey, mq.EventMessage{
		Type:      routingKey,
		EventID:   eventID,
		Source:    source,
		Payload:   payload,
		CreatedAt: time.Now().UTC(),
	})
}

func extractEventID(resp map[string]any) string {
	if v := asString(resp["event_id"]); v != "" {
		return v
	}
	if v := asString(resp["id"]); v != "" {
		return v
	}
	if data, ok := resp["data"].(map[string]any); ok {
		if v := asString(data["event_id"]); v != "" {
			return v
		}
		if v := asString(data["id"]); v != "" {
			return v
		}
	}
	return ""
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func newID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
}

// buildOccurrence 从一条 ly 事件构造单次命中记录：时间 + 数据包大小(wire_bytes) + 包数(packets)。
// wire_bytes/packets 缺失时省略对应键，便于前端区分"无数据"。
func buildOccurrence(ly map[string]any) map[string]any {
	occ := map[string]any{}
	t := firstNonEmpty(asString(ly["occurrence_time"]), asString(ly["time"]))
	if t != "" {
		occ["time"] = t
	}
	if v, ok := ly["wire_bytes"]; ok && v != nil {
		occ["wire_bytes"] = toInt(v)
	}
	if v, ok := ly["packets"]; ok && v != nil {
		occ["packets"] = toInt(v)
	}
	rp := nestedMap(ly, "raw_packet")
	if rp == nil {
		return occ
	}
	if v := asString(rp["message_direction"]); v != "" {
		occ["message_direction"] = v
	}
	if v := asString(rp["payload_text"]); v != "" {
		occ["payload_text"] = v
	}
	if v := asString(rp["payload_hex"]); v != "" {
		if len(v) > 1024 {
			occ["payload_hex"] = v[:1024]
			occ["payload_hex_truncated"] = true
		} else {
			occ["payload_hex"] = v
		}
	}
	if v, ok := rp["packet_sequence"]; ok && v != nil {
		occ["packet_sequence"] = toInt(v)
	}
	if v, ok := rp["captured_length"]; ok && v != nil {
		occ["captured_length"] = toInt(v)
	}
	if v, ok := rp["wire_length"]; ok && v != nil {
		occ["wire_length"] = toInt(v)
	}
	if v, ok := rp["capture_truncated"]; ok {
		occ["capture_truncated"] = v
	}
	if v := asString(rp["capture_time"]); v != "" {
		occ["capture_time"] = v
	}
	if v := asString(rp["session_start_time"]); v != "" {
		occ["session_start_time"] = v
	}
	if rm := nestedMap(rp, "request"); rm != nil {
		occ["request"] = map[string]any{
			"tcp_seq":        toInt(rm["tcp_seq"]),
			"tcp_ack":        toInt(rm["tcp_ack"]),
			"retransmission": rm["retransmission"],
		}
	}
	if rm := nestedMap(rp, "response"); rm != nil {
		occ["response"] = map[string]any{
			"tcp_seq":        toInt(rm["tcp_seq"]),
			"tcp_ack":        toInt(rm["tcp_ack"]),
			"retransmission": rm["retransmission"],
		}
	}
	return occ
}
