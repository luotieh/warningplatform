package client

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
)

// LLMCallError carries safe diagnostics through the business handler's 502 response.
type LLMCallError struct {
	Endpoint, Model, Reason, Detail string
	Status                          int
	MaxTokens                       int
	TokenParameter                  string
}

func (e *LLMCallError) Error() string {
	budget, parameter := e.MaxTokens, e.TokenParameter
	if budget == 0 {
		budget = chatMaxTokens
	}
	if parameter == "" {
		parameter = "max_tokens"
	}
	return fmt.Sprintf("LLM调用失败：%s；URL=%s；model=%s；status=%d；%s=%d；上游原因：%s", e.Reason, e.Endpoint, e.Model, e.Status, parameter, budget, e.Detail)
}

var llmCredentialPattern = regexp.MustCompile(`(?i)(bearer\s+\S+|sk-[a-z0-9_-]+)`)

func (c LLMClient) callError(endpoint string, status int, detail string) error {
	originalEndpoint := endpoint
	// URLs may carry credentials; never return userinfo, query values or fragments.
	if u, err := url.Parse(endpoint); err == nil {
		u.User, u.RawQuery, u.Fragment = nil, "", ""
		endpoint = u.String()
	}
	detail = strings.ReplaceAll(detail, originalEndpoint, endpoint)
	redact := func(s string) string {
		if key := strings.TrimSpace(c.APIKey); key != "" {
			s = strings.ReplaceAll(s, key, "[REDACTED]")
		}
		s = llmCredentialPattern.ReplaceAllString(s, "[REDACTED]")
		s = strings.Join(strings.Fields(s), " ")
		r := []rune(s)
		if len(r) > 2000 {
			s = string(r[:2000]) + "…"
		}
		return s
	}
	detail = redact(detail)
	reason := "上游请求失败，需根据上游原因确认"
	lower := strings.ToLower(detail)
	has := func(values ...string) bool {
		for _, v := range values {
			if strings.Contains(lower, v) {
				return true
			}
		}
		return false
	}
	switch {
	case has("context_length", "context window", "maximum context", "too many tokens", "上下文", "上下文长度"):
		reason = "上下文长度超限：减少输入或降低输出 token 预算"
	case status == 402 || has("insufficient_quota", "insufficient balance", "quota exceeded", "credit", "余额不足", "额度不足"):
		reason = "额度或余额不足：检查账户额度"
	case status == 401 || status == 403 || has("invalid_api_key", "invalid api key"):
		reason = "认证或权限问题：检查密钥及模型访问权限"
	case status == 429 || has("rate_limit", "rate limit"):
		reason = "请求限流：降低频率或稍后重试"
	case status == 404 || has("model_not_found", "model not found", "invalid model", "does not exist"):
		reason = "接口地址或模型配置问题：检查 URL 和模型名称"
	case has("timeout", "deadline exceeded"):
		reason = "请求超时：检查服务状态和超时配置"
	case status >= 500:
		reason = "上游服务异常"
	case status == 400 || status == 422:
		reason = "请求参数被拒绝：检查模型支持的参数及限制"
	case status == 0:
		reason = "请求未完成：检查网络、地址及请求配置"
	}
	result := &LLMCallError{Endpoint: redact(endpoint), Model: redact(c.Model), Status: status, Reason: reason, Detail: detail}
	slog.Warn("LLM请求失败", "error", result.Error())
	return result
}

func upstreamErrorDetail(body []byte) string {
	var out struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if json.Unmarshal(body, &out) == nil {
		var e struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    any    `json:"code"`
			Param   any    `json:"param"`
		}
		if json.Unmarshal(out.Error, &e) == nil && e.Message != "" {
			return fmt.Sprintf("%s (type=%s, code=%v, param=%v)", e.Message, e.Type, e.Code, e.Param)
		}
		var message string
		if json.Unmarshal(out.Error, &message) == nil && message != "" {
			return message
		}
		if out.Message != "" {
			return out.Message
		}
	}
	if strings.TrimSpace(string(body)) == "" {
		return "上游未提供错误详情"
	}
	return string(body)
}
