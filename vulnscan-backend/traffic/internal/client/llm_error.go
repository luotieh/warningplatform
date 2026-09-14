package client

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"
)

// LLMCallError preserves the failure layer instead of confusing an upstream
// authentication error with the platform's own HTTP authentication response.
type LLMCallError struct {
	Code string `json:"error_code"`
	Stage string `json:"stage"`
	Message string `json:"message"`
	Hint string `json:"hint"`
	UpstreamStatus int `json:"upstream_status,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func (e *LLMCallError) Error() string { return e.Message }

func callError(code, stage, message, hint string) *LLMCallError {
	return &LLMCallError{Code: code, Stage: stage, Message: message, Hint: hint}
}

var secretPattern = regexp.MustCompile(`(?i)(bearer\s+\S+|sk-[a-z0-9_-]+|(?:api[_-]?key|token|authorization)\s*[=:]\s*[^\s,;]+)`)

func safeLLMDetail(text, apiKey string) string {
	if apiKey != "" { text = strings.ReplaceAll(text, apiKey, "[已隐藏]") }
	text = secretPattern.ReplaceAllString(text, "[已隐藏]")
	runes := []rune(strings.TrimSpace(text))
	if len(runes) > 600 { return string(runes[:600]) + "…" }
	return string(runes)
}

func llmTransportError(err error) *LLMCallError {
	if errors.Is(err, context.Canceled) {
		return callError("request_cancelled", "upstream", "模型请求已中断", "连接已关闭；确认网络恢复后重新发送。")
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return callError("upstream_timeout", "upstream", "模型服务响应超时", "检查服务负载和超时配置；确认后重试，避免连续重复提交。")
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return callError("upstream_dns", "upstream", "无法解析模型服务域名", "检查模型地址、服务器 DNS 和代理设置。")
	}
	if strings.Contains(strings.ToLower(err.Error()), "certificate") || strings.Contains(strings.ToLower(err.Error()), "tls") {
		return callError("upstream_tls", "upstream", "模型服务 TLS 证书校验失败", "检查服务证书、域名和系统时间。")
	}
	return callError("upstream_connection", "upstream", "后端无法连接模型服务", "检查模型地址、端口、代理和防火墙，确认服务正在运行。")
}

func llmResponseError(status int, body []byte, apiKey string) *LLMCallError {
	// Extract only provider error fields, never echo an entire response or prompt.
	var envelope struct { Error json.RawMessage `json:"error"`; Message string `json:"message"` }
	var provider struct { Code any `json:"code"`; Type string `json:"type"`; Message string `json:"message"` }
	_ = json.Unmarshal(body, &envelope)
	_ = json.Unmarshal(envelope.Error, &provider)
	detail := provider.Message
	if detail == "" { _ = json.Unmarshal(envelope.Error, &detail) }
	if detail == "" { detail = envelope.Message }
	codeJSON, _ := json.Marshal(provider.Code)
	signal := strings.ToLower(detail + " " + provider.Type + " " + string(codeJSON))
	has := func(terms ...string) bool { for _, t := range terms { if strings.Contains(signal, t) { return true } }; return false }
	e := callError("upstream_rejected", "upstream", "模型服务拒绝了请求", "检查模型配置和服务商返回的错误详情。")
	switch {
	case has("insufficient_quota", "insufficient_balance", "insufficient credit", "insufficient balance", "billing_hard_limit", "credit balance", "余额不足", "额度不足", "quota exhausted", "quota exceeded", "exceeded your current quota"):
		e = callError("quota_exhausted", "upstream", "模型账户额度不足", "检查服务商余额、套餐和项目额度，补充额度或切换可用模型。")
	case status == 401:
		e = callError("upstream_auth", "upstream", "模型 API Key 无效或已过期", "在流量分析的模型配置中更新 API Key。")
	case status == 403:
		e = callError("upstream_forbidden", "upstream", "模型服务拒绝访问", "核对模型授权、账户状态及服务商 IP/地区限制。")
	case has("model_not_found", "model does not exist", "unknown model", "模型不存在"):
		e = callError("model_not_found", "upstream", "指定模型不存在或不可访问", "核对模型名称与该 API Key 可访问的模型列表。")
	case has("context_length", "context length", "maximum context", "max context", "too many tokens", "input tokens", "prompt too long", "prompt is too long", "exceeds the context", "上下文过长") || status == 413:
		e = callError("context_too_long", "upstream", "事件或聊天上下文超过模型限制", "缩短问题，或选择支持更长上下文的模型。")
	case has("content_filter", "content_policy", "safety policy"):
		e = callError("content_rejected", "upstream", "请求被模型服务的内容规则拦截", "检查问题和事件内容，按服务商规则调整后重试。")
	case status == 429:
		e = callError("upstream_rate_limit", "upstream", "模型服务限制了当前请求（429）", "稍后重试，并检查服务商速率和额度限制；仅凭 429 无法确定是否欠费。")
	case status == 402:
		e = callError("billing_required", "upstream", "模型服务要求处理计费问题", "检查服务商账户账单、余额及套餐状态。")
	case status == 404 || status == 405:
		e = callError("upstream_endpoint", "upstream", "模型接口路径或模型不可用", "核对 Base URL（常见为以 /v1 结尾）及模型名称；后端会追加 /chat/completions。")
	case status == 408 || status == 504:
		e = callError("upstream_timeout", "upstream", "模型服务或上游网关超时", "稍后重试，或检查模型服务负载与超时设置。")
	case status >= 500:
		e = callError("upstream_unavailable", "upstream", "模型服务暂时不可用", "服务商或模型网关发生错误，请稍后重试或切换服务。")
	case status == 400 || status == 422:
		e = callError("upstream_parameters", "upstream", "模型服务不接受当前请求参数", "检查模型是否支持 Chat Completions、max_tokens 和 temperature 等参数。")
	}
	e.UpstreamStatus = status
	e.Detail = safeLLMDetail(detail, apiKey)
	return e
}
