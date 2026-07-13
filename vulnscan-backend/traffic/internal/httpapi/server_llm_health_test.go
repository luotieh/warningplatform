package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/service"
)

// newMockOpenAIServer 模拟 OpenAI 兼容服务（vLLM/Qwen）：/v1/models 与 /v1/chat/completions。
func newMockOpenAIServer(t *testing.T, reply string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"qwen"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["model"] != "qwen" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":{"message":"model not found"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"` + reply + `"}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func postLLMHealth(t *testing.T, srv *Server, payload map[string]any) (int, map[string]any) {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/llm/health", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	var resp struct {
		Status string         `json:"status"`
		Data   map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v body=%s", err, rec.Body.String())
	}
	return rec.Code, resp.Data
}

// POST /api/llm/health 用请求体里的表单值（未保存）完成连通性 + 对话测试。
func TestLLMHealthTestEndpointWithFormValues(t *testing.T) {
	llm := newMockOpenAIServer(t, "你好，我是通义千问，一个由阿里云研发的大语言模型。")
	defer llm.Close()

	// 已保存配置故意留空/指向别处，验证请求体表单值生效
	srv := New(config.Config{}, service.Services{LLM: &client.LLMClient{}}, nil)

	code, data := postLLMHealth(t, srv, map[string]any{
		"base_url":        llm.URL + "/v1",
		"model":           "qwen",
		"timeout_seconds": 30,
	})
	if code != http.StatusOK {
		t.Fatalf("HTTP %d, want 200; data=%v", code, data)
	}
	if data["ok"] != true {
		t.Fatalf("整体应通过: %v", data)
	}
	conn, _ := data["connectivity"].(map[string]any)
	if conn == nil || conn["ok"] != true || conn["status_code"] != float64(200) {
		t.Fatalf("连通性结果错误: %v", conn)
	}
	if !strings.HasSuffix(conn["endpoint"].(string), "/v1/models") {
		t.Fatalf("连通性端点错误: %v", conn["endpoint"])
	}
	chat, _ := data["chat"].(map[string]any)
	if chat == nil || chat["ok"] != true {
		t.Fatalf("对话测试结果错误: %v", chat)
	}
	if !strings.Contains(chat["reply"].(string), "通义千问") {
		t.Fatalf("回复未透出: %v", chat["reply"])
	}
	if chat["question"] != "你好，请用一句话介绍你自己。" {
		t.Fatalf("测试问题错误: %v", chat["question"])
	}
}

// 服务不可达时返回 503，且两段检查均报错。
func TestLLMHealthTestEndpointUnreachable(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead.Close()

	srv := New(config.Config{}, service.Services{LLM: &client.LLMClient{}}, nil)
	code, data := postLLMHealth(t, srv, map[string]any{"base_url": dead.URL, "model": "qwen"})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP %d, want 503", code)
	}
	conn, _ := data["connectivity"].(map[string]any)
	if conn == nil || conn["ok"] == true || conn["error"] == "" {
		t.Fatalf("连通性应失败并带错误: %v", conn)
	}
}

// 请求体缺 base_url 时回退已保存配置。
func TestLLMHealthTestEndpointFallbackToSaved(t *testing.T) {
	llm := newMockOpenAIServer(t, "OK")
	defer llm.Close()

	saved := &client.LLMClient{BaseURL: llm.URL + "/v1", Model: "qwen"}
	srv := New(config.Config{}, service.Services{LLM: saved}, nil)

	code, data := postLLMHealth(t, srv, map[string]any{})
	if code != http.StatusOK || data["ok"] != true {
		t.Fatalf("回退已保存配置应通过: HTTP %d data=%v", code, data)
	}
	if data["base_url"] != llm.URL+"/v1" {
		t.Fatalf("base_url 回退错误: %v", data["base_url"])
	}
}
