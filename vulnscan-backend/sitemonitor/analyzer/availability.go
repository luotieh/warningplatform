package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
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
		output.DetailsJSON = fmt.Sprintf(`{"error":"%s"}`, snap.Error)
		return output, nil
	}

	issues := make([]map[string]any, 0)

	if snap.StatusCode >= 400 {
		output.HasIssue = true
		issues = append(issues, map[string]any{
			"type":   "http_error",
			"status": snap.StatusCode,
		})
	}

	headerIssues := a.checkSecurityHeaders(snap.Headers)
	issues = append(issues, headerIssues...)
	if len(headerIssues) > 0 {
		output.HasIssue = true
	}

	sslIssues := a.checkSSLIssues(snap)
	issues = append(issues, sslIssues...)
	if len(sslIssues) > 0 {
		output.HasIssue = true
	}

	if output.HasIssue {
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

func (a *AvailabilityAnalyzer) checkSecurityHeaders(headers map[string]string) []map[string]any {
	issues := make([]map[string]any, 0)

	normalized := make(map[string]string, len(headers))
	for k, v := range headers {
		normalized[k] = v
		for _, lk := range []string{k} {
			_ = lk
		}
	}

	headerChecks := a.loadHeaderChecks()
	for _, hc := range headerChecks {
		if _, ok := normalized[hc.Name]; !ok {
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
