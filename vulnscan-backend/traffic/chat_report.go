package traffic

import (
	"context"
	"regexp"
	"strings"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/realtime"
)

// Only direct commands are routed. Questions, negations and quoted instructions
// remain ordinary chat; packet contents are never used to choose the route.
var formalReportCommand = regexp.MustCompile(`^(请|麻烦|请帮我|帮我|请你|请为我|为我)?(现在|直接)?(重新生成|重新生成一份|再次生成|重新出具|重新出一份|重新生成一下|生成|生成一份|生成一下|出具|形成|刷新|更新)(当前事件的|该事件的|这个事件的|本事件的|当前事件|该事件|这个事件|本事件)?(正式研判报告|正式分析报告|正式报告|安全研判报告|事件研判报告|研判报告|分析报告|报告)(一下|吧|谢谢)?$`)

func isFormalReportCommand(message string) bool {
	message = strings.TrimSpace(message)
	message = strings.TrimRight(message, "。！!，,；; ")
	message = strings.Join(strings.Fields(message), "")
	return formalReportCommand.MatchString(message)
}

func (s *ChatService) requestFormalReport(ctx context.Context, event domain.Event, body map[string]any, text string) (map[string]any, error) {
	// Persist the request before dispatch so an accepted operation is traceable.
	userMessage, err := s.core.Store.AddMessage(domain.Message{
		EventID: event.EventID, MessageFrom: domain.RoleUser,
		MessageType: "report_request", MessageContent: text,
		RoundID: 1, MessageCategory: "engineer_chat", SenderType: "user",
		ChatSessionID: stringValue(body["chat_session_id"]),
		UserID:        stringValue(body["user_id"]), UserNickname: stringValue(body["user_nickname"]),
	})
	if err != nil {
		return nil, err
	}
	realtime.BroadcastMessage(event.EventID, userMessage)
	result, err := NewEventService(s.core).RefreshReport(ctx, event.EventID)
	if err != nil {
		return nil, err
	}
	reply := "正式研判报告任务已提交，将使用与自动报告相同的证据、结构和校验流程。完成后请查看事件报告；生成失败时请查看事件分析状态。"
	if result["status"] == "already_running" {
		reply = "该事件已有正式报告任务运行中，未重复提交。完成后请查看事件报告。"
	}
	ack, err := s.core.Store.AddMessage(domain.Message{
		EventID: event.EventID, MessageFrom: domain.RoleAssistant,
		MessageType: "report_request_status", MessageContent: reply,
		RoundID: 1, MessageCategory: "engineer_chat", SenderType: "ai",
		ChatSessionID: stringValue(body["chat_session_id"]),
	})
	if err != nil {
		// Submission already succeeded. Return its status rather than encouraging
		// a duplicate request because the acknowledgement could not be stored.
		result["acknowledgement_error"] = err.Error()
	} else {
		realtime.BroadcastMessage(event.EventID, ack)
		result["message"] = ack
	}
	result["route"] = "formal_report"
	result["reply"] = reply
	result["user_message"] = userMessage
	return result, nil
}
