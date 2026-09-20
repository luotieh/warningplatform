package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type LLMClient struct {
	BaseURL     string
	APIKey      string
	Model       string
	Temperature float64
	HTTP        *http.Client
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

// chatCompletionsEndpoint 归一化 OpenAI 兼容端点：
// 兼容 base_url 同时支持两种写法：
//   - "http://host:1025/v1"                    → http://host:1025/v1/chat/completions
//   - "http://host:1025/v1/chat/completions"   → 原样使用（不重复拼接）
func chatCompletionsEndpoint(baseURL string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return ""
	}
	if strings.HasSuffix(base, "/chat/completions") {
		return base
	}
	return base + "/chat/completions"
}

func (c LLMClient) HealthCheck(ctx context.Context) LLMHealth {
	h := LLMHealth{Configured: c.Enabled(), BaseURL: strings.TrimSpace(c.BaseURL), Model: strings.TrimSpace(c.Model)}
	if !h.Configured {
		h.Error = "LLM_BASE_URL is empty"
		return h
	}
	if h.Model == "" {
		h.Model = "deepseek-chat"
		c.Model = h.Model
	}
	start := time.Now()
	result, err := c.complete(ctx, "Return only OK.", "health", healthTestMaxTokens)
	h.Endpoint, h.LatencyMS = result.Endpoint, time.Since(start).Milliseconds()
	h.OK = err == nil
	if err != nil {
		h.Error = err.Error()
	}
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

// 推理模型可能将思考与正文共用输出预算；一句话的正文不代表总输出只需 64 tokens。
const healthTestMaxTokens = 1024

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
// 2) 对话测试：通过与报告相同的协议适配器发送固定问题并读取最终回复。
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
	conn := LLMConnectivity{Endpoint: llmAPIBase(baseURL) + "/models"}
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
	c.BaseURL, c.Model, c.HTTP = baseURL, model, httpClient
	start := time.Now()
	result, err := c.complete(ctx, "", healthTestQuestion, healthTestMaxTokens)
	chat := LLMChatTest{Endpoint: result.Endpoint, Question: healthTestQuestion, Reply: result.Reply, LatencyMS: time.Since(start).Milliseconds(), OK: err == nil}
	if err != nil {
		chat.Error = err.Error()
		chat.Hint = missingV1Hint(baseURL, result.Status)
	}
	return chat
}

// chatMaxTokens 是给模型输出预留的 token 上限。本地 16K 窗口下,input 约 10K,
// 输出预留 6K,避免 prompt 占满窗口把回答挤掉导致中途截断。
const ChatMaxTokens = 6000
const chatMaxTokens = ChatMaxTokens

// Chat 以指定的 system prompt 与 user prompt 调用 LLM。不同链路(自动分析/工程师对话)
// 传入各自的 system,避免复用同一段人格造成冲突与 token 浪费。
func (c LLMClient) Chat(ctx context.Context, systemPrompt, prompt string) (string, error) {
	if !c.Enabled() {
		return "", errors.New("LLM未配置，请先在配置页面填写可用的LLM服务地址")
	}
	result, err := c.complete(ctx, systemPrompt, prompt, chatMaxTokens)
	if err != nil {
		return "", err
	}
	return result.Reply, nil
}
