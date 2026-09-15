package traffic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestEngineerEstimateMatchesSentPromptWithoutCallingModelOrWriting(t *testing.T) {
	calls := 0
	var sent struct {
		Messages []struct{ Role, Content string }
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"报告完成"}}]}`))
	}))
	defer upstream.Close()
	st := store.NewMemoryStore()
	_, _ = st.CreateEvent(domain.Event{EventID: "estimate-test", Context: `{"occurrence_count":57}`})
	chat := NewChatService(trafficservice.Services{Store: st, LLM: &client.LLMClient{BaseURL: upstream.URL + "/v1", Model: "test-model", HTTP: &http.Client{Timeout: 180 * time.Second}}})
	estimate, err := chat.Estimate("estimate-test", "唯一当前问题")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 || len(st.ListMessages("estimate-test")) != 0 {
		t.Fatal("Preview had side effects")
	}
	if estimate["timeout_seconds"] != 180 || estimate["output_max_tokens"] != client.ChatMaxTokens {
		t.Fatal(estimate)
	}
	if _, err := chat.Send(context.Background(), map[string]any{"event_id": "estimate-test", "message": "唯一当前问题"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(sent.Messages) != 2 {
		t.Fatal("Unexpected model request count")
	}
	whole := sent.Messages[0].Content + sent.Messages[1].Content
	if estimate["estimated_input_tokens"] != trafficservice.EstimatePromptTokens(whole)+12 {
		t.Fatal("Preview differs from actual send")
	}
	if strings.Count(whole, "唯一当前问题") != 1 {
		t.Fatal("Current question duplicated in history")
	}
}
