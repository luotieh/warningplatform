package monitoragent

import (
	"encoding/json"
	"strings"

	"vulnscan-backend/sitemonitor/analyzer"
)

// BuildAvailabilityResultJSON 生成与前端 AvailabilityDetail 一致的嵌套结构。
func BuildAvailabilityResultJSON(snapshotJSON string, output *analyzer.Output) string {
	var snap PageSnapshot
	_ = json.Unmarshal([]byte(snapshotJSON), &snap)

	available := true
	if output != nil {
		available = !output.HasIssue
	} else {
		available = snap.Error == "" && (snap.StatusCode == 0 || snap.StatusCode < 400)
	}

	result := map[string]any{
		"available":       available,
		"url":             firstNonEmpty(snap.URL, snap.FinalURL),
		"status_code":     snap.StatusCode,
		"timing":          availabilityTimingFromSnapshot(&snap),
		"dns":             availabilityDNSFromSnapshot(&snap),
		"http":            availabilityHTTPFromSnapshot(&snap),
		"ssl":             availabilitySSLFromSnapshot(&snap),
		"errors":          []string{},
		"warnings":        []string{},
		"security_issues": []any{},
	}

	if snap.Error != "" {
		result["errors"] = []string{snap.Error}
	}

	if output != nil && output.DetailsJSON != "" {
		var details map[string]any
		if err := json.Unmarshal([]byte(output.DetailsJSON), &details); err == nil {
			if issues, ok := details["issues"].([]any); ok {
				result["security_issues"] = issues
			}
			if timing, ok := details["timing"].(map[string]any); ok {
				mergeTiming(result, timing)
			}
			if code, ok := details["status_code"].(float64); ok && snap.StatusCode == 0 {
				result["status_code"] = int(code)
			}
		}
	}

	raw, _ := json.Marshal(result)
	return string(raw)
}

func availabilityTimingFromSnapshot(snap *PageSnapshot) map[string]any {
	return map[string]any{
		"dns_ms":           snap.DNSMS,
		"tcp_connect_ms":   snap.TCPConnectMS,
		"tls_handshake_ms": snap.TLSHandshakeMS,
		"ttfb_ms":          snap.TTFBMS,
		"total_ms":         snap.TotalMS,
	}
}

func availabilityDNSFromSnapshot(snap *PageSnapshot) map[string]any {
	ips := snap.ResolvedIPs
	if ips == nil {
		ips = []string{}
	}
	return map[string]any{
		"resolved_ips":      ips,
		"dns_consistent":    true,
		"multi_dns":         map[string]any{},
		"expected_ip_match": nil,
	}
}

func availabilityHTTPFromSnapshot(snap *PageSnapshot) map[string]any {
	headers := snap.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	respHeaders := make(map[string]string, len(headers))
	for k, v := range headers {
		respHeaders[k] = v
	}
	contentLen := snap.ContentLength
	if contentLen <= 0 && snap.RenderedHTML != "" {
		contentLen = int64(len(snap.RenderedHTML))
	}
	return map[string]any{
		"method":           "GET",
		"final_url":        firstNonEmpty(snap.FinalURL, snap.URL),
		"content_length":   contentLen,
		"keyword_found":    nil,
		"redirect_chain":   []any{},
		"response_headers": respHeaders,
	}
}

func availabilitySSLFromSnapshot(snap *PageSnapshot) map[string]any {
	enabled := strings.HasPrefix(strings.ToLower(firstNonEmpty(snap.FinalURL, snap.URL)), "https://")
	if snap.SSLIssuer != "" || snap.SSLProtocol != "" {
		enabled = true
	}
	out := map[string]any{
		"enabled":          enabled,
		"is_valid":         snap.SSLValid,
		"days_remaining":   snap.SSLDaysLeft,
		"protocol_version": snap.SSLProtocol,
		"cipher_suite":     snap.SSLCipher,
		"chain_complete":   snap.SSLChainComplete,
		"issuer":           snap.SSLIssuer,
		"subject":          snap.SSLSubject,
		"san":              snap.SSLSAN,
		"errors":           snap.SSLErrors,
	}
	if !snap.SSLExpiry.IsZero() {
		out["not_after"] = snap.SSLExpiry.Format("2006-01-02 15:04:05")
	}
	if !snap.SSLNotBefore.IsZero() {
		out["not_before"] = snap.SSLNotBefore.Format("2006-01-02 15:04:05")
	}
	return out
}

func mergeTiming(result map[string]any, timing map[string]any) {
	dst, _ := result["timing"].(map[string]any)
	if dst == nil {
		dst = map[string]any{}
	}
	for k, v := range timing {
		dst[k] = v
	}
	result["timing"] = dst
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
