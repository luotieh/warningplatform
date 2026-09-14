package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type LLMClient struct {
	BaseURL string
	APIKey  string
	Model   string
	Temperature float64
	HTTP    *http.Client
}

func (c LLMClient) temperature() float64 { if c.Temperature == 0 { return 1 }; return c.Temperature }

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
		// The configured k3 model only accepts temperature=1, including
		// lightweight health checks. Keep this consistent with Chat().
		"temperature": c.temperature(),
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

// LLMConnectivity 是健康检查第一段：对 /models 端点的连通性探测结果。
// OK 表示 HTTP 请求完成（服务网络可达），status_code 用于进一步判断路径/鉴权是否正确。
type LLMConnectivity struct {
	OK         bool   `json:"ok"`
	Endpoint   string `json:"endpoint,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	LatencyMS  int64  `json:"latency_ms,omitempty"`
	Error      string `json:"error,omitempty"`
	Hint       string `json:"hint,omitempty"`
}

// LLMChatTest 是健康检查第二段：发送一条真实对话并回读模型回复。
type LLMChatTest struct {
	OK        bool   `json:"ok"`
	Endpoint  string `json:"endpoint,omitempty"`
	Question  string `json:"question,omitempty"`
	Reply     string `json:"reply,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

// LLMHealthReport 汇总一次完整健康检查：连通性 + 对话测试。
type LLMHealthReport struct {
	Configured   bool            `json:"configured"`
	OK           bool            `json:"ok"`
	BaseURL      string          `json:"base_url,omitempty"`
	Model        string          `json:"model,omitempty"`
	Connectivity LLMConnectivity `json:"connectivity"`
	Chat         LLMChatTest     `json:"chat"`
}

// healthTestQuestion 是对话测试所发的固定问题，回复直接展示给用户看。
const healthTestQuestion = "你好，请用一句话介绍你自己。"

// healthTestMaxTokens 限制对话测试回复长度：只为验证链路可用，无需长回答。
const healthTestMaxTokens = 64

// WithOverrides 返回应用了表单临时参数的客户端副本：非空字段覆盖当前值，
// 空字段沿用已保存配置（与配置保存接口语义一致，api_key 掩码展示不回传）。
// 用于健康检查在"未保存"状态下测试页面上正在编辑的参数。
func (c LLMClient) WithOverrides(baseURL, model, apiKey string, timeoutSeconds int) LLMClient {
	if v := strings.TrimSpace(baseURL); v != "" {
		c.BaseURL = v
	}
	if v := strings.TrimSpace(model); v != "" {
		c.Model = v
	}
	if v := strings.TrimSpace(apiKey); v != "" {
		c.APIKey = v
	}
	if timeoutSeconds > 0 {
		c.HTTP = &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}
	}
	return c
}

// missingV1Hint 在 404 时提示常见配置错误：OpenAI 兼容服务(vLLM 等)的
// 服务地址需要带 /v1 前缀，例如 http://127.0.0.1:1025/v1。
func missingV1Hint(baseURL string, statusCode int) string {
	if statusCode == http.StatusNotFound && !strings.Contains(baseURL, "/v1") {
		return "服务地址可能缺少 /v1 前缀（如 http://127.0.0.1:1025/v1）"
	}
	return ""
}

// HealthTest 对 LLM 服务做两段式健康检查：
// 1) 连通性：GET {base_url}/models，任何 HTTP 应答都说明服务可达；
// 2) 对话测试：POST {base_url}/chat/completions 发送一条固定问题并回读回复。
// 与 Chat 使用相同的端点拼接约定，检查通过即代表自动分析链路可用。
func (c LLMClient) HealthTest(ctx context.Context) LLMHealthReport {
	report := LLMHealthReport{
		Configured: c.Enabled(),
		BaseURL:    strings.TrimRight(strings.TrimSpace(c.BaseURL), "/"),
		Model:      strings.TrimSpace(c.Model),
	}
	if !report.Configured {
		report.Connectivity.Error = "服务地址为空，请先填写LLM服务地址"
		report.Chat.Error = "服务地址为空，请先填写LLM服务地址"
		return report
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	report.Connectivity = c.connectivityCheck(ctx, httpClient, report.BaseURL)
	report.Chat = c.chatTest(ctx, httpClient, report.BaseURL, report.Model)
	report.OK = report.Connectivity.OK && report.Chat.OK
	return report
}

func (c LLMClient) connectivityCheck(ctx context.Context, httpClient *http.Client, baseURL string) LLMConnectivity {
	conn := LLMConnectivity{Endpoint: baseURL + "/models"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, conn.Endpoint, nil)
	if err != nil {
		conn.Error = err.Error()
		return conn
	}
	if key := strings.TrimSpace(c.APIKey); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	start := time.Now()
	resp, err := httpClient.Do(req)
	conn.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		conn.Error = "无法连接LLM服务: " + err.Error()
		return conn
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	conn.OK = true
	conn.StatusCode = resp.StatusCode
	conn.Hint = missingV1Hint(baseURL, resp.StatusCode)
	return conn
}

func (c LLMClient) chatTest(ctx context.Context, httpClient *http.Client, baseURL, model string) LLMChatTest {
	chat := LLMChatTest{
		Endpoint: baseURL + "/chat/completions",
		Question: healthTestQuestion,
	}
	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": healthTestQuestion},
		},
		"max_tokens": healthTestMaxTokens,
		"stream":     false,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		chat.Error = err.Error()
		return chat
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, chat.Endpoint, bytes.NewReader(b))
	if err != nil {
		chat.Error = err.Error()
		return chat
	}
	req.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(c.APIKey); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	start := time.Now()
	resp, err := httpClient.Do(req)
	chat.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		chat.Error = "对话请求失败: " + err.Error()
		return chat
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
		chat.Error = fmt.Sprintf("响应解析失败(status=%d): %v", resp.StatusCode, err)
		chat.Hint = missingV1Hint(baseURL, resp.StatusCode)
		return chat
	}
	if resp.StatusCode >= 400 {
		chat.Error = fmt.Sprintf("对话请求失败: status=%d error=%v", resp.StatusCode, out.Error)
		chat.Hint = missingV1Hint(baseURL, resp.StatusCode)
		return chat
	}
	if len(out.Choices) == 0 {
		chat.Error = "LLM未返回有效内容(choices为空)"
		return chat
	}
	chat.Reply = strings.TrimSpace(out.Choices[0].Message.Content)
	chat.OK = true
	return chat
}

// chatMaxTokens 是给模型输出预留的 token 上限。本地 16K 窗口下,input 约 10K,
// 输出预留 6K,避免 prompt 占满窗口把回答挤掉导致中途截断。
const chatMaxTokens = 6000

// Chat 以指定的 system prompt 与 user prompt 调用 LLM。不同链路(自动分析/工程师对话)
// 传入各自的 system,避免复用同一段人格造成冲突与 token 浪费。
func (c LLMClient) Chat(ctx context.Context, systemPrompt, prompt string) (string, error) {
	if !c.Enabled() {
		return "", callError("model_not_configured", "configuration", "模型服务地址未配置", "请在流量分析 → 配置 → 模型中保存服务地址和模型名称。")
	}
	if strings.TrimSpace(c.Model) == "" {
		return "", callError("model_not_configured", "configuration", "模型名称未配置", "请在流量分析的模型配置中填写模型名称。")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	parsed, parseErr := url.Parse(baseURL)
	if parseErr != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", callError("model_invalid_url", "configuration", "模型服务地址格式无效", "请填写完整的 http:// 或 https:// Base URL。")
	}
	payload := map[string]any{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": prompt},
		},
		"stream":      false,
		"max_tokens":  chatMaxTokens,
		// The configured k3 endpoint only accepts temperature=1.
		"temperature": c.temperature(),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(b))
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
		return "", llmTransportError(err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil { return "", llmTransportError(err) }
	if resp.StatusCode >= 400 {
		return "", llmResponseError(resp.StatusCode, responseBody, c.APIKey)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &out); err != nil {
		return "", callError("upstream_invalid_response", "upstream", "模型返回了无法解析的响应", "确认接口返回 OpenAI 兼容 JSON，而非 HTML 网关页面或流式响应。")
	}
	if out.Error != nil { return "", llmResponseError(resp.StatusCode, responseBody, c.APIKey) }
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", callError("upstream_empty_response", "upstream", "模型没有返回有效的回答", "检查模型是否支持当前对话接口，或稍后重试。")
	}
	return out.Choices[0].Message.Content, nil
}
