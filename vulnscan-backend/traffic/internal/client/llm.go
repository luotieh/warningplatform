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

func (c LLMClient) Chat(ctx context.Context, prompt string) (string, error) {
	if !c.Enabled() {
		return "", errors.New("LLM未配置，请先在配置页面填写可用的LLM服务地址")
	}
	systemPrompt := `你是 DeepSOC 安全运营中心的 AI 助手，专门协助安全工程师处理安全事件。
回答必须基于用户提供的事件信息、AI分析概要、自动驾驶过程和历史对话，不要编造未给出的日志、资产或情报事实。
你的输出要体现 SOC 实战深度：先研判事件本质，再梳理证据链、影响面、风险等级、验证步骤、处置建议和后续监控。
如果信息不足，要明确指出缺口，并给出下一步应查询的数据和可执行动作。保持中文、专业、结构化。`
	payload := map[string]any{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": prompt},
		},
		"stream": false,
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
