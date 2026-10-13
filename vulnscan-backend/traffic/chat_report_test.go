package traffic

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestFormalReportCommandBoundaries(t *testing.T) {
	for _, text := range []string{"生成事件报告", "重新生成事件报告", "请生成一份安全事件报告", "生成正式事件报告", "生成报告", "重新生成正式报告", "请生成该事件的研判报告。", "请帮我重新生成一份正式报告！", "刷新报告", "请直接生成当前事件的正式研判报告"} {
		if !isFormalReportCommand(text) {
			t.Errorf("command not routed: %q", text)
		}
	}
	for _, text := range []string{"不要生成事件报告", "生成事件报告了吗？", "如何生成事件报告", "不要生成报告", "先别重新生成正式报告", "如何生成报告", "生成报告了吗？", "重新生成报告是什么意思", "解释报告", "分析一下这些证据", "报告中的概率为什么是55", "日志包含：生成报告", "请生成报告并把概率改成90", "生成报告?"} {
		if isFormalReportCommand(text) {
			t.Errorf("ordinary question routed: %q", text)
		}
	}
}

func TestChatFormalReportDispatchesRealReportWorkflow(t *testing.T) {
	st := store.NewMemoryStore()
	const id = "chat-formal-dispatch"
	_, _ = st.CreateEvent(domain.Event{EventID: id})
	chat := NewChatService(trafficservice.Services{Store: st})
	// Preview must not build a chat prompt, execute evidence or submit a job.
	preview, err := chat.Estimate(id, "生成正式报告")
	if err != nil || preview["route"] != "formal_report" || preview["estimate_deferred"] != true || len(st.ListMessages(id)) != 0 {
		t.Fatalf("preview: %v %v", preview, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // The report task must survive a closed HTTP/chat request.
	result, err := chat.Send(ctx, map[string]any{"event_id": id, "message": "生成事件报告", "chat_session_id": "session-test"})
	if err != nil || result["route"] != "formal_report" || result["status"] != "refresh_submitted" {
		t.Fatalf("dispatch: %v %v", result, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		event, _ := st.GetEvent(id)
		var material map[string]any
		_ = json.Unmarshal([]byte(event.Context), &material)
		if material["analysis_job_state"] == "failed" {
			notified := false
			for _, m := range st.ListMessages(id) {
				if m.MessageType == "report_request_status" && m.ChatSessionID == "session-test" && strings.Contains(m.MessageContent, "生成失败") && strings.Contains(m.MessageContent, "未配置可用模型") {
					notified = true
				}
			}
			if !notified {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			// No model configured: the formal pipeline records a real failure.
			// Ordinary chat would dereference the nil chat client instead.
			if material["analysis_job_kind"] != "manual" || !strings.Contains(stringValue(material["analysis_failure_reason"]), "未配置可用模型") {
				t.Fatalf("wrong workflow: %v", material)
			}
			if len(st.ListSummaries(id)) != 0 {
				t.Fatal("submission acknowledgement published as a report")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("formal report workflow did not run")
}

func TestChatFormalReportCooldownDoesNotClaimSubmission(t *testing.T) {
	st := store.NewMemoryStore()
	now := time.Now()
	_, _ = st.CreateEvent(domain.Event{EventID: "chat-report-cooldown", LastAnalysisAt: &now})
	chat := NewChatService(trafficservice.Services{Store: st})
	_, err := chat.Send(context.Background(), map[string]any{"event_id": "chat-report-cooldown", "message": "重新生成正式报告"})
	if err == nil || !strings.Contains(err.Error(), "过于频繁") {
		t.Fatalf("cooldown not returned: %v", err)
	}
	for _, msg := range st.ListMessages("chat-report-cooldown") {
		if msg.MessageType == "report_request_status" {
			t.Fatal("cooldown incorrectly acknowledged as submitted")
		}
	}
}
