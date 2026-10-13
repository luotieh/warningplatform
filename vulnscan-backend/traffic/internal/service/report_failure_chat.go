package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/realtime"
	"vulnscan-backend/traffic/internal/store"
)

// Failure state is already committed. A failed notification must not undo it.
func (s Services) notifyReportFailure(id string) error {
	key, err := s.analysisEventLockKey(id)
	if err != nil {
		return err
	}
	var messages []domain.Message
	err = s.Store.AggregationTransaction(context.Background(), key, func(tx store.Store) error {
		messages = nil // A database transaction may retry; broadcast committed rows only.
		e, ok := tx.GetEvent(id)
		if !ok {
			return fmt.Errorf("report event not found")
		}
		c := decodeEventContext(e.Context)
		if c["analysis_job_state"] != "failed" {
			return nil
		}
		started := asString(c["analysis_started_at"])
		reason := asString(c["analysis_failure_reason"])
		identity := started + "|" + asString(c["analysis_failed_at"]) + "|" + reason
		if c["report_failure_chat_notified"] == identity {
			return nil
		}
		at, parseErr := time.Parse(time.RFC3339Nano, started)
		if parseErr != nil {
			return nil
		}
		// Submission persists the request just before marking the task running.
		// Requests arriving during an existing task also receive its final failure.
		requests := map[string]domain.Message{}
		for _, m := range tx.ListMessages(id) {
			if m.MessageType != "report_request" || m.MessageCategory != "engineer_chat" || m.CreatedAt.Before(at.Add(-time.Second)) {
				continue
			}
			if old, exists := requests[m.ChatSessionID]; !exists || m.CreatedAt.After(old.CreatedAt) {
				requests[m.ChatSessionID] = m
			}
		}
		if len(requests) == 0 {
			return nil
		}
		for session := range requests {
			m, saveErr := tx.AddMessage(domain.Message{EventID: id, MessageFrom: domain.RoleAssistant, MessageType: "report_request_status", MessageCategory: "engineer_chat", SenderType: "ai", RoundID: 1, ChatSessionID: session,
				MessageContent: "正式研判报告生成失败：" + reason + "。本次未发布新报告或更新概率；已有报告及概率保留。请查看报告日志定位原因，修复后重新生成。"})
			if saveErr != nil {
				return saveErr
			}
			messages = append(messages, m)
		}
		c["report_failure_chat_notified"] = identity
		raw, marshalErr := json.Marshal(c)
		if marshalErr != nil {
			return marshalErr
		}
		if _, ok := tx.UpdateEvent(id, map[string]any{"context": string(raw)}); !ok {
			return fmt.Errorf("save report notification state failed")
		}
		return nil
	})
	if err == nil {
		for _, m := range messages {
			realtime.BroadcastMessage(id, m)
		}
	}
	return err
}
