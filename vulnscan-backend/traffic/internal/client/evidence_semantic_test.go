package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"vulnscan-backend/evidence"
)

func TestEvidenceSemanticModelBudgetAndTruncation(t *testing.T) {
	for _, finish := range []string{"stop", "length"} {
		t.Run(finish, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body["max_tokens"] != float64(800) {
					t.Errorf("semantic output budget lost: %v", body["max_tokens"])
				}
				messages, ok := body["messages"].([]any)
				if !ok || len(messages) != 2 {
					t.Errorf("missing bounded messages: %v", body["messages"])
				}
				fmt.Fprintf(w, `{"choices":[{"finish_reason":%q,"message":{"content":"{\"items\":[]}"}}]}`, finish)
			}))
			defer srv.Close()
			m := EvidenceSemanticModel{Client: LLMClient{BaseURL: srv.URL, Model: "fixture", HTTP: srv.Client(), MaxTokens: 6000}}
			text, err := m.Complete(context.Background(), evidence.SemanticCall{System: "system", Prompt: "bounded", MaxOutputTokens: 800})
			if finish == "stop" && (err != nil || text != `{"items":[]}`) {
				t.Fatalf("text=%q err=%v", text, err)
			}
			if finish == "length" && err == nil {
				t.Fatal("truncated semantic output accepted")
			}
			if m.Client.MaxTokens != 6000 {
				t.Fatal("report client budget mutated")
			}
		})
	}
}

func TestEvidenceSemanticModelUnavailable(t *testing.T) {
	m := EvidenceSemanticModel{}
	if _, err := m.Complete(context.Background(), evidence.SemanticCall{MaxOutputTokens: 800}); err == nil {
		t.Fatal("unconfigured model accepted")
	}
	if _, err := m.Complete(context.Background(), evidence.SemanticCall{}); err == nil {
		t.Fatal("empty budget accepted")
	}
}
