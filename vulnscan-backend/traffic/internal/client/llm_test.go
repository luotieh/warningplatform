package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Chat 必须携带独立的 system prompt、显式 max_tokens(给输出留空间)与低 temperature。
func TestChatSendsSystemPromptAndOutputBudget(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"分析结果"}}]}`))
	}))
	defer srv.Close()

	c := LLMClient{BaseURL: srv.URL, Model: "qwen32b"}
	reply, err := c.Chat(context.Background(), "SYSTEM-PROMPT", "USER-PROMPT")
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if reply != "分析结果" {
		t.Fatalf("reply = %q, want 分析结果", reply)
	}

	if mt, ok := got["max_tokens"].(float64); !ok || int(mt) != chatMaxTokens {
		t.Fatalf("max_tokens = %v, want %d", got["max_tokens"], chatMaxTokens)
	}
	if _, ok := got["temperature"]; !ok {
		t.Fatalf("temperature must be set for structured output")
	}

	msgs, ok := got["messages"].([]any)
	if !ok || len(msgs) != 2 {
		t.Fatalf("messages = %v, want 2 entries", got["messages"])
	}
	sys := msgs[0].(map[string]any)
	usr := msgs[1].(map[string]any)
	if sys["role"] != "system" || sys["content"] != "SYSTEM-PROMPT" {
		t.Fatalf("system message = %v", sys)
	}
	if usr["role"] != "user" || usr["content"] != "USER-PROMPT" {
		t.Fatalf("user message = %v", usr)
	}
}
