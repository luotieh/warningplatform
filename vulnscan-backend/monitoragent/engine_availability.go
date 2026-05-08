package monitoragent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type AvailabilityEngine struct {
	Rules RuleStore
}

func (e *AvailabilityEngine) Name() string { return "availability" }

func (e *AvailabilityEngine) Run(ctx context.Context, task *TaskMessage, snap *PageSnapshot) (map[string]any, error) {
	result := map[string]any{
		"url":       task.URL,
		"available": true,
	}

	if snap == nil || snap.Error != "" {
		result["available"] = false
		if snap != nil {
			result["error"] = snap.Error
		}
		return result, nil
	}

	result["status_code"] = snap.StatusCode
	result["title"] = snap.Title

	result["timing"] = map[string]any{
		"dns_ms":           snap.DNSMS,
		"tcp_connect_ms":   snap.TCPConnectMS,
		"tls_handshake_ms": snap.TLSHandshakeMS,
		"ttfb_ms":          snap.TTFBMS,
		"total_ms":         snap.TotalMS,
	}

	dnsInfo := map[string]any{
		"resolved_ips": snap.ResolvedIPs,
	}
	dnsCheck := e.checkDNS(ctx, task.URL)
	if dnsCheck != nil {
		dnsInfo["dns_consistent"] = dnsCheck["consistent"]
		dnsInfo["multi_dns"] = dnsCheck["resolvers"]
	}
	result["dns"] = dnsInfo

	httpInfo := map[string]any{
		"method":         "GET",
		"content_length": len(snap.RenderedHTML),
		"final_url":      snap.FinalURL,
	}
	if len(snap.Headers) > 0 {
		httpInfo["response_headers"] = snap.Headers
	}
	result["http"] = httpInfo

	if snap.StatusCode >= 400 {
		result["available"] = false
		result["reason"] = fmt.Sprintf("HTTP %d", snap.StatusCode)
	}

	if strings.HasPrefix(task.URL, "https://") {
		cipherStrength := "strong"
		if snap.SSLProtocol == "TLS 1.0" || snap.SSLProtocol == "TLS 1.1" {
			cipherStrength = "weak"
		} else if snap.SSLProtocol == "TLS 1.2" {
			cipherStrength = "acceptable"
		}

		sslInfo := map[string]any{
			"enabled":          true,
			"is_valid":         snap.SSLValid,
			"issuer":           snap.SSLIssuer,
			"subject":          snap.SSLSubject,
			"days_remaining":   snap.SSLDaysLeft,
			"protocol_version": snap.SSLProtocol,
			"cipher_suite":     snap.SSLCipher,
			"cipher_strength":  cipherStrength,
			"chain_complete":   snap.SSLChainComplete,
			"chain_depth":      snap.SSLChainDepth,
			"san":              snap.SSLSAN,
			"serial_number":    snap.SSLSerialNumber,
			"signature_alg":    snap.SSLSignatureAlg,
			"key_bits":         snap.SSLKeyBits,
		}
		if !snap.SSLExpiry.IsZero() {
			sslInfo["not_after"] = snap.SSLExpiry.Format(time.RFC3339)
		}
		if !snap.SSLNotBefore.IsZero() {
			sslInfo["not_before"] = snap.SSLNotBefore.Format(time.RFC3339)
		}
		if len(snap.SSLErrors) > 0 {
			sslInfo["errors"] = snap.SSLErrors
		}
		result["ssl"] = sslInfo
	}

	secIssues := e.checkSecurityHeaders(snap.Headers, strings.HasPrefix(task.URL, "https://"))
	if len(secIssues) > 0 {
		result["security_issues"] = secIssues
	}

	return result, nil
}

func (e *AvailabilityEngine) checkSecurityHeaders(headers map[string]string, isHTTPS bool) []map[string]any {
	var issues []map[string]any

	normalizedHeaders := make(map[string]string, len(headers))
	for k, v := range headers {
		normalizedHeaders[strings.ToLower(k)] = v
	}

	headerChecks := e.loadHeaderChecks()
	for _, hc := range headerChecks {
		val := normalizedHeaders[strings.ToLower(hc.Name)]
		if hc.Name == "Strict-Transport-Security" && !isHTTPS {
			continue
		}
		if val == "" {
			issues = append(issues, map[string]any{
				"type":     "missing_security_header",
				"name":     hc.Name,
				"severity": hc.Severity,
				"detail":   hc.Description,
			})
		}
	}

	infoLeakHeaders := e.loadInfoLeakHeaders()
	for _, ilh := range infoLeakHeaders {
		if val := normalizedHeaders[strings.ToLower(ilh.Name)]; val != "" {
			issues = append(issues, map[string]any{
				"type":     "information_disclosure",
				"name":     ilh.Name,
				"severity": ilh.Severity,
				"detail":   fmt.Sprintf("%s: %s", ilh.Description, val),
			})
		}
	}

	return issues
}

type availRuleEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type dnsResolverEntry struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

func (e *AvailabilityEngine) loadDNSResolvers() []string {
	if e.Rules == nil {
		return nil
	}
	data, err := e.Rules.GetModuleRules("common")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		PublicDNS []dnsResolverEntry `json:"public_dns"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	resolvers := make([]string, 0, len(cfg.PublicDNS))
	for _, d := range cfg.PublicDNS {
		if d.IP != "" {
			resolvers = append(resolvers, d.IP+":53")
		}
	}
	return resolvers
}

func (e *AvailabilityEngine) loadHeaderChecks() []availRuleEntry {
	if e.Rules == nil {
		return nil
	}
	data, err := e.Rules.GetModuleRules("availability")
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

func (e *AvailabilityEngine) loadInfoLeakHeaders() []availRuleEntry {
	if e.Rules == nil {
		return nil
	}
	data, err := e.Rules.GetModuleRules("availability")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		InfoLeakHeaders []availRuleEntry `json:"info_leak_headers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return cfg.InfoLeakHeaders
}

func (e *AvailabilityEngine) checkDNS(ctx context.Context, rawURL string) map[string]any {
	host := extractHost(rawURL)
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}

	resolvers := e.loadDNSResolvers()
	if len(resolvers) == 0 {
		return nil
	}
	results := make(map[string][]string, len(resolvers))

	for _, resolver := range resolvers {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", resolver)
			},
		}

		dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := r.LookupHost(dnsCtx, host)
		cancel()
		if err == nil {
			results[resolver] = addrs
		}
	}

	consistent := true
	var firstSet []string
	for _, addrs := range results {
		if firstSet == nil {
			firstSet = addrs
			continue
		}
		if !sameIPs(firstSet, addrs) {
			consistent = false
			break
		}
	}

	return map[string]any{
		"resolvers":  results,
		"consistent": consistent,
	}
}

func (e *AvailabilityEngine) checkHTTPSRedirect(ctx context.Context, url string) bool {
	if !strings.HasPrefix(url, "http://") {
		return false
	}

	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		return strings.HasPrefix(loc, "https://")
	}
	return false
}

func extractHost(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rawURL = rawURL[idx+3:]
	}
	if idx := strings.Index(rawURL, "/"); idx >= 0 {
		rawURL = rawURL[:idx]
	}
	if idx := strings.Index(rawURL, ":"); idx >= 0 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}

func sameIPs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, ip := range a {
		set[ip] = true
	}
	for _, ip := range b {
		if !set[ip] {
			return false
		}
	}
	return true
}
