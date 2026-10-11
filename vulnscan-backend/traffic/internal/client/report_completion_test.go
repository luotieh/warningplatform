package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReportThinkingControlDoesNotChangeOrdinaryChat(t *testing.T) {
	requests := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid request")
		}
		requests = append(requests, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"content":"OK"}}],"usage":{"prompt_tokens":20,"completion_tokens":2}}`))
	}))
	defer server.Close()
	ordinary := LLMClient{BaseURL: server.URL, Model: "K2.7", HTTP: server.Client()}
	report := ordinary
	report.ReportThinkingDisabled = true
	if _, err := report.CompleteReport(context.Background(), "system", "prompt"); err != nil {
		t.Fatal(err)
	}
	if _, err := ordinary.Chat(context.Background(), "system", "prompt"); err != nil {
		t.Fatal(err)
	}
	control, ok := requests[0]["thinking"].(map[string]any)
	if !ok || control["type"] != "disabled" {
		t.Fatal("report control missing")
	}
	if _, exists := requests[1]["thinking"]; exists {
		t.Fatal("ordinary caller changed")
	}
}
