package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type LLMClient struct {
	BaseURL string
	APIKey  string
	Model   string
	HTTP    *http.Client
}

type LLMHealth struct {
	Configured bool   `json:"configured"`
	OK         bool   `json:"ok"`
	BaseURL    string `json:"base_url,omitempty"`
	Model      string `json:"model,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	LatencyMS  int64  `json:"latency_ms,omitempty"`
	Error      string `json:"error,omitempty"`
}

func (c LLMClient) Enabled() bool {
	// 只要配置了 base_url 即视为可用：本地部署的 LLM 往往无需鉴权，api_key 为空是合法的。
	// 真正能否调用由 HealthCheck 实际请求端点来判定，而不是凭 api_key 是否为空。
	return strings.TrimSpace(c.BaseURL) != ""
}

func (c LLMClient) HealthCheck(ctx context.Context) LLMHealth {
	h := LLMHealth{
		Configured: c.Enabled(),
		BaseURL:    strings.TrimRight(strings.TrimSpace(c.BaseURL), "/"),
		Model:      strings.TrimSpace(c.Model),
	}
	if h.BaseURL != "" {
		h.Endpoint = h.BaseURL + "/chat/completions"
	}
	if h.Model == "" {
		h.Model = "deepseek-chat"
	}
	if !h.Configured {
		h.Error = "LLM_BASE_URL is empty"
		return h
	}

	payload := map[string]any{
		"model": h.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "Return only OK."},
			{"role": "user", "content": "health"},
		},
		"stream":      false,
		"max_tokens":  4,
		"temperature": 0,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.Endpoint, bytes.NewReader(b))
	if err != nil {
		h.Error = err.Error()
		return h
	}
	req.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(c.APIKey); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	start := time.Now()
	resp, err := httpClient.Do(req)
	h.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		h.Error = err.Error()
		return h
	}
	defer resp.Body.Close()

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error any `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		h.Error = err.Error()
		return h
	}
	if resp.StatusCode >= 400 {
		h.Error = fmt.Sprintf("llm request failed: status=%d error=%v", resp.StatusCode, out.Error)
		return h
	}
	if len(out.Choices) == 0 {
		h.Error = "llm returned empty choices"
		return h
	}
	h.OK = true
	return h
}

// chatMaxTokens 是给模型输出预留的 token 上限。本地 16K 窗口下,input 约 10K,
// 输出预留 6K,避免 prompt 占满窗口把回答挤掉导致中途截断。
const chatMaxTokens = 6000

// Chat 以指定的 system prompt 与 user prompt 调用 LLM。不同链路(自动分析/工程师对话)
// 传入各自的 system,避免复用同一段人格造成冲突与 token 浪费。
func (c LLMClient) Chat(ctx context.Context, systemPrompt, prompt string) (string, error) {
	if !c.Enabled() {
		return "", errors.New("LLM未配置，请先在配置页面填写可用的LLM服务地址")
	}
	payload := map[string]any{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": prompt},
		},
		"stream":      false,
		"max_tokens":  chatMaxTokens,
		"temperature": 0.2,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(c.APIKey); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("LLM调用失败，请检查LLM配置: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error any `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("LLM调用失败，请检查LLM配置: status=%d", resp.StatusCode)
	}
	if len(out.Choices) == 0 {
		return "", errors.New("LLM未返回有效内容，请检查LLM配置")
	}
	return out.Choices[0].Message.Content, nil
}
