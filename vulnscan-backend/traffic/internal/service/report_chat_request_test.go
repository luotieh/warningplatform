package service

import (
	"strings"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestReportDialogueExcludesDispatchMessages(t *testing.T) {
	st := store.NewMemoryStore()
	if _, err := st.CreateEvent(domain.Event{EventID: "report-command-dialogue"}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []domain.Message{
		{MessageType: "report_request", MessageContent: "生成正式报告"},
		{MessageType: "report_request_status", MessageContent: "任务已提交"},
		{MessageType: "user_message", MessageContent: "该资产是内部DNS服务器"},
	} {
		m.EventID, m.MessageCategory, m.MessageFrom = "report-command-dialogue", "engineer_chat", domain.RoleUser
		if _, err := st.AddMessage(m); err != nil {
			t.Fatal(err)
		}
	}
	got := (Services{Store: st}).dialogueEvidenceSection("report-command-dialogue")
	if strings.Contains(got, "生成正式报告") || strings.Contains(got, "任务已提交") || !strings.Contains(got, "内部DNS服务器") {
		t.Fatal(got)
	}
}
