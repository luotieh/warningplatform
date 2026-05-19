package agent

import (
	"fmt"
	"regexp"
	"strings"

	"vulnscan-backend/pkg/clusterconn"
)

var reWhitespace = regexp.MustCompile(`\s+`)

// FormatHTTPErrorBody 将 HTTP 错误正文压缩为简短中文说明，避免把整页 HTML 打进日志。
func FormatHTTPErrorBody(body []byte) string {
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "无响应正文"
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "<!doctype") || strings.HasPrefix(lower, "<html") {
		return "主控返回了 HTML 页面（请确认 master_url 含 /api 前缀，且已转发 /node-api/health）"
	}
	s = reWhitespace.ReplaceAllString(s, " ")
	const maxLen = 160
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}

// FormatErrorDetail 格式化 error 供终端展示。
func FormatErrorDetail(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if idx := strings.Index(msg, "<!DOCTYPE"); idx >= 0 {
		msg = strings.TrimSpace(msg[:idx])
	}
	if idx := strings.Index(strings.ToLower(msg), "<html"); idx >= 0 {
		msg = strings.TrimSpace(msg[:idx])
	}
	msg = reWhitespace.ReplaceAllString(msg, " ")
	const maxLen = 240
	if len(msg) > maxLen {
		msg = msg[:maxLen] + "…"
	}
	return msg
}

// FormatMasterConnectError 连接主控失败时的完整提示。
func FormatMasterConnectError(masterURL string, err error, topology string) error {
	if err == nil {
		return nil
	}
	hint := clusterconn.AgentConnectivityHint(topology)
	detail := FormatErrorDetail(err)
	if strings.Contains(detail, "unsupported protocol scheme") {
		hint = "master_url 不是完整地址（当前可能仅为 /api）；请在 agent.toml 设置 master_url=http://127.0.0.1:8090/api，并检查凭据 JSON 中的 master_url"
	}
	return fmt.Errorf("无法连接主控 %s: %s（%s）",
		strings.TrimSpace(masterURL),
		detail,
		hint,
	)
}
