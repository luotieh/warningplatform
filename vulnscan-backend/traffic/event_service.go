package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
)

// aggregateIdleWindow 聚合收敛窗口：距最近一次命中超过该时长无新增，即判定已收敛，
// 此刻的发生次数视为该聚合事件的“最终频次”。
const aggregateIdleWindow = 10 * time.Minute

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

func (s *EventService) Detail(ctx context.Context, eventID string) (domain.Event, bool) {
	return s.core.Store.GetEvent(eventID)
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
	return map[string]any{
		"event_id":     eventID,
		"messages":     len(s.core.Store.ListMessages(eventID)),
		"tasks":        len(s.core.Store.ListTasks(eventID)),
		"actions":      len(s.core.Store.ListActions(eventID)),
		"commands":     len(s.core.Store.ListCommands(eventID)),
		"executions":   len(s.core.Store.ListExecutions(eventID)),
		"summaries":    len(s.core.Store.ListSummaries(eventID)),
		"generated_at": time.Now().UTC(),
	}
}

func (s *EventService) Summaries(ctx context.Context, eventID string) []domain.Summary {
	return s.core.Store.ListSummaries(eventID)
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
	eventType := firstNonEmpty(stringValue(context["event_type"]), stringValue(context["type"]), "cap")
	level := lyLevel(event.Severity)
	startTime := event.CreatedAt.Unix()
	if v, ok := unixLike(context["occurrence_time"]); ok {
		startTime = v
	}
	analysisStatus := analysisStatusForEvent(event.EventStatus)

	// 静默超时收敛判定：距服务器最近一次收到该聚合命中超过 aggregateIdleWindow
	// 仍无新增 ⟹ 已收敛(closed)，此刻 occurrence_count 即“最终频次”。
	lastSeen, _ := time.Parse(time.RFC3339, stringValue(context["last_seen_at"]))
	if lastSeen.IsZero() {
		lastSeen = event.UpdatedAt
	}
	isFinal := !lastSeen.IsZero() && time.Since(lastSeen) >= aggregateIdleWindow
	aggregationStatus := "active"
	if isFinal {
		aggregationStatus = "closed"
	}

	return map[string]any{
		"id":                firstNonEmpty(event.EventID, stringValue(event.ID)),
		"event_id":          event.EventID,
		"attackDevice":      source,
		"victimDevice":      destination,
		"obj":               source + ">" + destination,
		"type":              eventType,
		"level":             level,
		"desc":              firstNonEmpty(event.EventName, event.Title, event.Message),
		"rule_desc":         firstNonEmpty(event.EventName, event.Title, event.Message),
		"proc_status":       "unprocessed",
		"processing_status": "unprocessed",
		"analysis_status":   analysisStatus,
		"analysisStatus":    analysisStatus,
		"starttime":         startTime,
		"time":              startTime,
		"duration":          context["duration"],
		"is_alive":          true,
		"is_active":         true,
		"show_model":        firstNonEmpty(stringValue(context["detection_method"]), stringValue(context["protocol"])),
		"source":            event.Source,
		// 聚合信息：发生次数与首/末次时间（同来源+目标+类型、仅时间不同的事件已合并为一条）
		"event_count": context["occurrence_count"],
		"first_time":  stringValue(context["first_time"]),
		"last_time":   stringValue(context["last_time"]),
		// 收敛状态：active=进行中(可能继续)，closed=已收敛(occurrence_count 即最终频次)
		"aggregation_status": aggregationStatus,
		"is_final":           isFinal,
		// 每次命中明细：时间 + 数据包大小(wire_bytes) + 包数(packets)，供前端命中频次弹窗
		"occurrences": context["occurrences"],
		// 审核状态：供事件列表展示「待审核/已通过/已驳回」与通报编号
		"review_status": event.ReviewStatus,
		"circular_code": event.CircularCode,
	}
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
