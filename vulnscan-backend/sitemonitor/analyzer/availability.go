package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type AvailabilityAnalyzer struct {
	rules RuleAccessor
}

func NewAvailabilityAnalyzer(rules RuleAccessor) *AvailabilityAnalyzer {
	return &AvailabilityAnalyzer{rules: rules}
}

func (a *AvailabilityAnalyzer) Dimension() string { return "availability" }

func (a *AvailabilityAnalyzer) Analyze(ctx context.Context, input *Input) (*Output, error) {
	snap, err := parseSnapshot(input.SnapshotJSON)
	if err != nil {
		return nil, err
	}

	output := &Output{HasIssue: false}

	if snap.Error != "" {
		output.HasIssue = true
		output.Severity = "high"
		detailJSON, _ := json.Marshal(map[string]any{"error": snap.Error})
		output.DetailsJSON = string(detailJSON)
		return output, nil
	}

	issues := make([]map[string]any, 0)

	if snap.StatusCode >= 500 {
		issues = append(issues, map[string]any{
			"type":     "http_server_error",
			"status":   snap.StatusCode,
			"severity": "critical",
		})
	} else if snap.StatusCode >= 400 {
		issues = append(issues, map[string]any{
			"type":     "http_client_error",
			"status":   snap.StatusCode,
			"severity": "high",
		})
	}

	aliveIssues := a.checkAliveKeywords(snap, input.Config)
	issues = append(issues, aliveIssues...)

	contentIssues := a.checkContentAnomalies(snap)
	issues = append(issues, contentIssues...)

	headerIssues := a.checkSecurityHeaders(snap.Headers)
	issues = append(issues, headerIssues...)

	sslIssues := a.checkSSLIssues(snap)
	issues = append(issues, sslIssues...)

	timingIssues := a.checkTimingAnomalies(snap)
	issues = append(issues, timingIssues...)

	if len(issues) > 0 {
		output.HasIssue = true
		output.Severity = classifyAvailSeverity(issues)
		detailJSON, _ := json.Marshal(map[string]any{
			"issues":      issues,
			"status_code": snap.StatusCode,
			"timing": map[string]float64{
				"dns_ms":           snap.DNSMS,
				"tcp_connect_ms":   snap.TCPConnectMS,
				"tls_handshake_ms": snap.TLSHandshakeMS,
				"ttfb_ms":          snap.TTFBMS,
				"total_ms":         snap.TotalMS,
			},
		})
		output.DetailsJSON = string(detailJSON)
	}

	return output, nil
}

func classifyAvailSeverity(issues []map[string]any) string {
	maxSev := "low"
	rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	for _, issue := range issues {
		if sev, ok := issue["severity"].(string); ok {
			if rank[sev] > rank[maxSev] {
				maxSev = sev
			}
		}
	}
	return maxSev
}

func (a *AvailabilityAnalyzer) checkTimingAnomalies(snap *snapshotData) []map[string]any {
	var issues []map[string]any

	if snap.TTFBMS > 5000 {
		issues = append(issues, map[string]any{
			"type":     "slow_ttfb",
			"ttfb_ms":  snap.TTFBMS,
			"severity": "medium",
			"detail":   fmt.Sprintf("TTFB %.0fms 超过 5 秒阈值，服务器响应过慢", snap.TTFBMS),
		})
	}
	if snap.TotalMS > 15000 {
		issues = append(issues, map[string]any{
			"type":     "slow_total",
			"total_ms": snap.TotalMS,
			"severity": "high",
			"detail":   fmt.Sprintf("总响应时间 %.0fms 超过 15 秒", snap.TotalMS),
		})
	}
	if snap.DNSMS > 3000 {
		issues = append(issues, map[string]any{
			"type":     "slow_dns",
			"dns_ms":   snap.DNSMS,
			"severity": "medium",
			"detail":   fmt.Sprintf("DNS 解析 %.0fms 异常缓慢", snap.DNSMS),
		})
	}
	return issues
}

func (a *AvailabilityAnalyzer) checkSecurityHeaders(headers map[string]string) []map[string]any {
	issues := make([]map[string]any, 0)

	normalized := make(map[string]string, len(headers))
	for k, v := range headers {
		normalized[strings.ToLower(k)] = v
	}

	headerChecks := a.loadHeaderChecks()
	for _, hc := range headerChecks {
		if _, ok := normalized[strings.ToLower(hc.Name)]; !ok {
			issues = append(issues, map[string]any{
				"type":     "missing_security_header",
				"name":     hc.Name,
				"severity": hc.Severity,
				"detail":   hc.Description,
			})
		}
	}

	return issues
}

func (a *AvailabilityAnalyzer) checkSSLIssues(snap *snapshotData) []map[string]any {
	issues := make([]map[string]any, 0)

	if !snap.SSLValid && snap.SSLIssuer != "" {
		issues = append(issues, map[string]any{
			"type":      "ssl_invalid",
			"days_left": snap.SSLDaysLeft,
			"issuer":    snap.SSLIssuer,
			"severity":  "critical",
		})
	}

	if snap.SSLDaysLeft > 0 && snap.SSLDaysLeft < 30 {
		issues = append(issues, map[string]any{
			"type":      "ssl_expiring",
			"days_left": snap.SSLDaysLeft,
			"severity":  "medium",
		})
	}

	if snap.SSLProtocol == "TLS 1.0" || snap.SSLProtocol == "TLS 1.1" {
		issues = append(issues, map[string]any{
			"type":     "weak_tls",
			"protocol": snap.SSLProtocol,
			"severity": "high",
		})
	}

	return issues
}

type availRuleEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

func (a *AvailabilityAnalyzer) checkAliveKeywords(snap *snapshotData, config map[string]any) []map[string]any {
	var issues []map[string]any

	keywords := extractAliveKeywords(config)
	if len(keywords) == 0 {
		return nil
	}

	text := strings.ToLower(snap.VisibleText + " " + snap.Title)
	var missing []string
	for _, kw := range keywords {
		if !strings.Contains(text, strings.ToLower(kw)) {
			missing = append(missing, kw)
		}
	}

	if len(missing) > 0 {
		severity := "medium"
		if len(missing) == len(keywords) {
			severity = "high"
		}
		issues = append(issues, map[string]any{
			"type":             "alive_keyword_missing",
			"missing_keywords": missing,
			"total_keywords":   len(keywords),
			"severity":         severity,
			"detail":           fmt.Sprintf("页面缺少 %d/%d 个存活关键词，页面内容可能已被替换", len(missing), len(keywords)),
		})
	}

	return issues
}

func extractAliveKeywords(config map[string]any) []string {
	if config == nil {
		return nil
	}
	v, ok := config["alive_keywords"]
	if !ok {
		return nil
	}
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if arr != "" {
			return strings.Split(arr, ",")
		}
	}
	return nil
}

func (a *AvailabilityAnalyzer) checkContentAnomalies(snap *snapshotData) []map[string]any {
	var issues []map[string]any

	if snap.StatusCode == 200 {
		textLen := len([]rune(snap.VisibleText))
		if textLen < 50 && snap.Title == "" {
			issues = append(issues, map[string]any{
				"type":     "empty_page",
				"severity": "high",
				"detail":   fmt.Sprintf("页面返回200但内容极少（%d字符且无标题），可能为空白劫持页", textLen),
			})
		}

		if snap.FinalURL != "" && snap.URL != "" {
			origDomain := extractHost(snap.URL)
			finalDomain := extractHost(snap.FinalURL)
			if origDomain != "" && finalDomain != "" && origDomain != finalDomain {
				issues = append(issues, map[string]any{
					"type":         "cross_domain_redirect",
					"severity":     "high",
					"original_url": snap.URL,
					"final_url":    snap.FinalURL,
					"detail":       fmt.Sprintf("页面被重定向到不同域名（%s → %s），可能遭到劫持", origDomain, finalDomain),
				})
			}
		}

		if snap.MetaRedirect != nil {
			metaDomain := extractHost(snap.MetaRedirect.URL)
			pageDomain := extractHost(snap.URL)
			if metaDomain != "" && pageDomain != "" && metaDomain != pageDomain {
				issues = append(issues, map[string]any{
					"type":     "meta_redirect_external",
					"severity": "high",
					"url":      snap.MetaRedirect.URL,
					"seconds":  snap.MetaRedirect.Seconds,
					"detail":   fmt.Sprintf("页面包含指向外域的meta跳转(%s, %ds后)", metaDomain, snap.MetaRedirect.Seconds),
				})
			}
		}
	}

	return issues
}

func (a *AvailabilityAnalyzer) loadHeaderChecks() []availRuleEntry {
	if a.rules == nil {
		return nil
	}
	data, err := a.rules.GetModuleRules("availability")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		HTTPHeadersCheck []availRuleEntry `json:"http_headers_check"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return cfg.HTTPHeadersCheck
}
