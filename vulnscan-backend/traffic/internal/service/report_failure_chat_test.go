package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestReportNotificationTransactionRollsBackMessageWrites(t *testing.T) {
	st := store.NewMemoryStore()
	st.CreateEvent(domain.Event{EventID: "notification-rollback"})
	err := st.AggregationTransaction(context.Background(), "notification-rollback", func(tx store.Store) error {
		if _, err := tx.AddMessage(domain.Message{EventID: "notification-rollback", MessageFrom: domain.RoleAssistant, MessageType: "report_request_status"}); err != nil {
			return err
		}
		return errors.New("injected failure")
	})
	if err == nil || len(st.ListMessages("notification-rollback")) != 0 {
		t.Fatal("failed transaction leaked notification")
	}
}

func TestReportFailureNotifiesRequestSessionsOnceAndPreservesProbability(t *testing.T) {
	s := Services{Store: store.NewMemoryStore()}
	_, _ = s.Store.CreateEvent(domain.Event{EventID: "failure-chat", Context: `{"ai_probability":55,"report_published":true}`})
	_, _ = s.Store.AddMessage(domain.Message{EventID: "failure-chat", MessageType: "report_request", MessageCategory: "engineer_chat", ChatSessionID: "stale", CreatedAt: time.Now().Add(-time.Hour)})
	if err := s.setAnalysisJob("failure-chat", "running", "manual"); err != nil {
		t.Fatal(err)
	}
	for _, session := range []string{"a", "a", "b"} {
		_, _ = s.Store.AddMessage(domain.Message{EventID: "failure-chat", MessageType: "report_request", MessageCategory: "engineer_chat", ChatSessionID: session})
	}
	for i := 0; i < 2; i++ {
		if err := s.setAnalysisJob("failure-chat", "failed", "", "report_fact_numbers_not_in_cited_scope: value=secret-url"); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]int{}
	for _, m := range s.Store.ListMessages("failure-chat") {
		if m.MessageType != "report_request_status" {
			continue
		}
		seen[m.ChatSessionID]++
		if !strings.Contains(m.MessageContent, "数量或时间与引用证据不一致") || strings.Contains(m.MessageContent, "secret") {
			t.Fatalf("unsafe or missing cause: %s", m.MessageContent)
		}
	}
	if len(seen) != 2 || seen["a"] != 1 || seen["b"] != 1 {
		e, _ := s.Store.GetEvent("failure-chat")
		t.Fatalf("notifications: %v context=%s messages=%+v", seen, e.Context, s.Store.ListMessages(e.EventID))
	}
	e, _ := s.Store.GetEvent("failure-chat")
	if toInt(decodeEventContext(e.Context)["ai_probability"]) != 55 || len(s.Store.ListSummaries(e.EventID)) != 0 {
		t.Fatal("failure changed published probability/report")
	}
}

func TestAutomaticReportFailureDoesNotCreateUnsolicitedChat(t *testing.T) {
	s := Services{Store: store.NewMemoryStore()}
	s.Store.CreateEvent(domain.Event{EventID: "automatic-no-chat"})
	s.setAnalysisJob("automatic-no-chat", "running", "initial")
	s.setAnalysisJob("automatic-no-chat", "failed", "", "report_success_or_exclusion_overclaim")
	if len(s.Store.ListMessages("automatic-no-chat")) != 0 {
		t.Fatal("automatic failure invented chat request")
	}
}
