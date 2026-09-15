package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChatUpstreamDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body, want string
	}{
		{"context", 400, `{"error":{"message":"maximum context length is 8192 tokens", "code":"context_length_exceeded"}}`, "上下文长度超限"},
		{"quota", 429, `{"error":{"message":"quota exceeded", "code":"insufficient_quota"}}`, "额度或余额不足"},
		{"rate", 429, `{"error":"rate limit exceeded"}`, "请求限流"},
		{"auth", 401, `{"error":{"message":"invalid key sk-example"}}`, "认证或权限问题"},
		{"model", 404, `{"message":"model not found"}`, "模型配置问题"},
		{"parameter", 400, `{"error":{"message":"temperature must be 1", "param":"temperature"}}`, "请求参数被拒绝"},
		{"text", 503, "upstream temporarily unavailable", "上游服务异常"},
		{"empty", 502, "", "上游未提供错误详情"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := LLMClient{BaseURL: srv.URL + "/v1", Model: "configured-model", APIKey: "sk-example"}
			_, err := c.Chat(context.Background(), "system", "question")
			var detail *LLMCallError
			if !errors.As(err, &detail) || detail.Status != tc.status {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, want := range []string{tc.want, srv.URL + "/v1/chat/completions", "model=configured-model", "max_tokens=6000"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("missing %q: %v", want, err)
				}
			}
			if strings.Contains(err.Error(), c.APIKey) {
				t.Fatal("API key leaked")
			}
		})
	}
}

func TestLLMErrorRedactsURLAndLimitsDetail(t *testing.T) {
	c := LLMClient{Model: "test", APIKey: "private-key"}
	endpoint := "https://user:password@example.com/v1/chat/completions?api_key=other-secret"
	err := c.callError(endpoint, 0, endpoint+" private-key Bearer token-value "+strings.Repeat("x", 4000))
	for _, secret := range []string{"password", "other-secret", "private-key", "token-value"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	if len([]rune(err.Error())) > 2400 {
		t.Fatal("error not bounded")
	}
}
