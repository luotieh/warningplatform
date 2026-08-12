package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// HealthTest 正常路径：/models 连通 + 对话测试拿到回复，请求体与固定问题一致。
func TestHealthTestHappyPath(t *testing.T) {
	var chatBody map[string]any
	var chatAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"qwen"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
			chatAuth = r.Header.Get("Authorization")
			_ = json.NewDecoder(r.Body).Decode(&chatBody)
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":" 我是通义千问。 "}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := LLMClient{BaseURL: srv.URL + "/v1/", Model: "qwen", APIKey: "sk-test"}
	report := c.HealthTest(context.Background())

	if !report.Configured || !report.OK {
		t.Fatalf("report 应整体通过: %+v", report)
	}
	if !report.Connectivity.OK || report.Connectivity.StatusCode != 200 {
		t.Fatalf("连通性检查失败: %+v", report.Connectivity)
	}
	if report.Connectivity.Endpoint != srv.URL+"/v1/models" {
		t.Fatalf("连通性端点错误: %q", report.Connectivity.Endpoint)
	}
	if !report.Chat.OK || report.Chat.Reply != "我是通义千问。" {
		t.Fatalf("对话测试失败: %+v", report.Chat)
	}
	if report.Chat.Question != healthTestQuestion {
		t.Fatalf("问题 = %q, want %q", report.Chat.Question, healthTestQuestion)
	}
	if chatAuth != "Bearer sk-test" {
		t.Fatalf("Authorization = %q", chatAuth)
	}
	if mt, _ := chatBody["max_tokens"].(float64); int(mt) != healthTestMaxTokens {
		t.Fatalf("max_tokens = %v, want %d", chatBody["max_tokens"], healthTestMaxTokens)
	}
	if stream, ok := chatBody["stream"].(bool); !ok || stream {
		t.Fatalf("stream = %v, want false", chatBody["stream"])
	}
	if chatBody["model"] != "qwen" {
		t.Fatalf("model = %v", chatBody["model"])
	}
	msgs, _ := chatBody["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("对话测试应只有一条 user 消息: %v", chatBody["messages"])
	}
	if usr := msgs[0].(map[string]any); usr["role"] != "user" || usr["content"] != healthTestQuestion {
		t.Fatalf("user message = %v", usr)
	}
}

// 服务不可达：两段都失败并给出网络错误。
func TestHealthTestUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // 立即关闭拿到一个必然拒绝连接的地址

	c := LLMClient{BaseURL: srv.URL, Model: "qwen"}
	report := c.HealthTest(context.Background())
	if report.OK || report.Connectivity.OK || report.Chat.OK {
		t.Fatalf("不可达服务不应通过: %+v", report)
	}
	if report.Connectivity.Error == "" || report.Chat.Error == "" {
		t.Fatalf("应有错误信息: %+v", report)
	}
}

// 缺 /v1 前缀：连通(有 HTTP 应答)但 404，对话失败且提示补 /v1。
func TestHealthTestMissingV1Hint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // 模拟 vLLM：/models、/chat/completions 只在 /v1 下存在
	}))
	defer srv.Close()

	c := LLMClient{BaseURL: srv.URL, Model: "qwen"}
	report := c.HealthTest(context.Background())
	if !report.Connectivity.OK || report.Connectivity.StatusCode != 404 {
		t.Fatalf("有 HTTP 应答即视为可达: %+v", report.Connectivity)
	}
	if report.Chat.OK || report.OK {
		t.Fatalf("404 不应通过对话测试: %+v", report.Chat)
	}
	if !strings.Contains(report.Connectivity.Hint, "/v1") || !strings.Contains(report.Chat.Hint, "/v1") {
		t.Fatalf("应提示缺少 /v1: conn=%q chat=%q", report.Connectivity.Hint, report.Chat.Hint)
	}
}

// 上游返回错误对象：透出 status 与 error 内容。
func TestHealthTestUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models" {
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"model not found"}}`))
	}))
	defer srv.Close()

	c := LLMClient{BaseURL: srv.URL, Model: "nope"}
	report := c.HealthTest(context.Background())
	if !report.Connectivity.OK {
		t.Fatalf("连通性应通过: %+v", report.Connectivity)
	}
	if report.Chat.OK || !strings.Contains(report.Chat.Error, "status=400") || !strings.Contains(report.Chat.Error, "model not found") {
		t.Fatalf("应透出上游错误: %+v", report.Chat)
	}
}

// 未配置服务地址：直接失败，不发请求。
func TestHealthTestNotConfigured(t *testing.T) {
	report := LLMClient{}.HealthTest(context.Background())
	if report.Configured || report.OK {
		t.Fatalf("未配置不应通过: %+v", report)
	}
	if report.Connectivity.Error == "" || report.Chat.Error == "" {
		t.Fatalf("应有提示信息: %+v", report)
	}
}

// WithOverrides：非空覆盖、空值回退、timeout 生成独立 HTTP 客户端。
func TestWithOverrides(t *testing.T) {
	base := LLMClient{BaseURL: "http://saved:1025/v1", Model: "saved-model", APIKey: "saved-key"}

	probe := base.WithOverrides(" http://form:2025/v1 ", "", "", 30)
	if probe.BaseURL != "http://form:2025/v1" {
		t.Fatalf("base_url 未覆盖: %q", probe.BaseURL)
	}
	if probe.Model != "saved-model" || probe.APIKey != "saved-key" {
		t.Fatalf("空字段应回退保存值: %+v", probe)
	}
	if probe.HTTP == nil || probe.HTTP.Timeout != 30*time.Second {
		t.Fatalf("timeout 未生效: %+v", probe.HTTP)
	}
	if base.HTTP != nil {
		t.Fatalf("WithOverrides 不应修改原客户端")
	}

	same := base.WithOverrides("", "", "", 0)
	if same.BaseURL != base.BaseURL || same.Model != base.Model || same.APIKey != base.APIKey || same.HTTP != nil {
		t.Fatalf("全空参数应保持原配置: %+v", same)
	}
}

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

func TestChatCompletionsEndpointNormalization(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"http://127.0.0.1:1025/v1", "http://127.0.0.1:1025/v1/chat/completions"},
		{"http://127.0.0.1:1025/v1/", "http://127.0.0.1:1025/v1/chat/completions"},
		{"http://127.0.0.1:1025/v1/chat/completions", "http://127.0.0.1:1025/v1/chat/completions"},
		{"http://127.0.0.1:1025/v1/chat/completions/", "http://127.0.0.1:1025/v1/chat/completions"},
		{"", ""},
	}
	for _, c := range cases {
		if got := chatCompletionsEndpoint(c.base); got != c.want {
			t.Fatalf("chatCompletionsEndpoint(%q) = %q, want %q", c.base, got, c.want)
		}
	}
}
