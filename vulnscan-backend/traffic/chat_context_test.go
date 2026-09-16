package traffic

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestEngineerPromptSamplesPacketDetailsWithoutChangingEvent(t *testing.T) {
	occurrences := make([]any, 200)
	for i := range occurrences {
		occurrences[i] = map[string]any{"time": fmt.Sprintf("hit-%03d", i), "payload_text": strings.Repeat("sample", 150), "payload_hex": strings.Repeat("ab", 512)}
	}
	raw, _ := json.Marshal(map[string]any{
		"occurrences": occurrences, "occurrence_count": 500, "first_time": "first", "last_time": "last",
		"src_ip": "192.0.2.1", "demo_details": map[string]any{"synthetic": true},
	})
	ev := domain.Event{EventID: "evt-prompt", Context: string(raw)}
	st := store.NewMemoryStore()
	if _, err := st.CreateEvent(ev); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		_, err := st.AddMessage(domain.Message{EventID: ev.EventID, MessageCategory: "engineer_chat", SenderType: "ai", MessageContent: fmt.Sprintf("turn-%02d ", i) + strings.Repeat("历史报告内容", 2000)})
		if err != nil {
			t.Fatal(err)
		}
	}
	chat := NewChatService(trafficservice.Services{Store: st})
	prompt := chat.engineerEventPrompt(ev, "请基于证据重新生成报告")
	for _, want := range []string{"E-evt-prompt-O1", "明细数=500", "可索引明细数=200", `"synthetic":true`, "turn-24", "请基于证据重新生成报告"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(prompt, `"payload_hex":`) || strings.Contains(prompt, "turn-00") {
		t.Fatal("Unbounded evidence or old history leaked into prompt")
	}
	if len([]rune(prompt)) > 11000 {
		t.Fatalf("oversized prompt: %d runes", len([]rune(prompt)))
	}
	saved, _ := st.GetEvent(ev.EventID)
	if saved.Context != string(raw) || ev.Context != string(raw) {
		t.Fatal("Original event context changed")
	}
}

func TestEngineerContextBoundsLegacyAndLargeContexts(t *testing.T) {
	for _, raw := range []string{strings.Repeat("旧上下文", 10000), `{"nested":{"large":"` + strings.Repeat("x", 20000) + `"}}`} {
		if got := compactEngineerContext(raw); len([]rune(got)) > engineerContextMaxRunes {
			t.Fatalf("context exceeds budget: %d", len([]rune(got)))
		}
	}
}
