package scanrunner

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"code.yt-security.com/public/scanengine/core"

	"vulnscan-backend/scan/scanhttp"
)

// VulnVerifier performs secondary verification of vulnerability findings
// by replaying requests and checking for exploit indicators.
type VulnVerifier struct {
	httpClient *scanhttp.ScanHTTPClient
	timeout    time.Duration
	maxRetries int
}

func NewVulnVerifier(client *scanhttp.ScanHTTPClient) *VulnVerifier {
	return &VulnVerifier{
		httpClient: client,
		timeout:    10 * time.Second,
		maxRetries: 2,
	}
}

// VerifyFindings performs secondary verification on vuln findings.
// Returns only verified findings; principle-only findings are downgraded or removed.
func (v *VulnVerifier) VerifyFindings(ctx context.Context, findings []*core.Finding, rejectPrinciple bool) []*core.Finding {
	if len(findings) == 0 {
		return findings
	}

	var (
		verified   []*core.Finding
		downgraded int32
		removed    int32
		mu         sync.Mutex
		wg         sync.WaitGroup
	)

	sem := make(chan struct{}, 10) // concurrency limit

	for _, f := range findings {
		if f == nil {
			continue
		}

		if f.Verified {
			mu.Lock()
			verified = append(verified, f)
			mu.Unlock()
			continue
		}

		if f.VerificationLevel == core.VerifyExploit {
			mu.Lock()
			verified = append(verified, f)
			mu.Unlock()
			continue
		}

		cat := inferCategory(f)
		if cat != "vuln" {
			mu.Lock()
			verified = append(verified, f)
			mu.Unlock()
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(finding *core.Finding) {
			defer wg.Done()
			defer func() { <-sem }()

			result := v.verifySingleFinding(ctx, finding)

			mu.Lock()
			defer mu.Unlock()

			switch result {
			case verifyConfirmed:
				finding.Verified = true
				finding.VerificationLevel = core.VerifyExploit
				finding.VerificationDetail = "二次验证通过"
				if finding.Confidence < 90 {
					finding.Confidence = 90
				}
				verified = append(verified, finding)

			case verifyDemoted:
				atomic.AddInt32(&downgraded, 1)
				if rejectPrinciple {
					atomic.AddInt32(&removed, 1)
				} else {
					finding.VerificationLevel = core.VerifyPrinciple
					finding.VerificationDetail = "仅原理验证，未能二次确认"
					if finding.Confidence > 40 {
						finding.Confidence = 40
					}
					finding.Severity = demoteSeverity(finding.Severity)
					verified = append(verified, finding)
				}

			case verifyFailed:
				atomic.AddInt32(&removed, 1)
			}
		}(f)
	}

	wg.Wait()

	slog.Info("[VulnVerifier] 验证完成",
		"input", len(findings),
		"verified", len(verified),
		"downgraded", downgraded,
		"removed", removed,
	)

	return verified
}

type verifyResult int

const (
	verifyConfirmed verifyResult = iota
	verifyDemoted
	verifyFailed
)

func (v *VulnVerifier) verifySingleFinding(ctx context.Context, f *core.Finding) verifyResult {
	if f.Target == nil || f.Target.URL == "" {
		return v.verifyByEvidence(f)
	}

	if isVersionOnlyFinding(f) {
		return verifyDemoted
	}

	if hasExploitEvidence(f) {
		return verifyConfirmed
	}

	for i := 0; i < v.maxRetries; i++ {
		result := v.replayHTTP(ctx, f)
		if result != verifyFailed {
			return result
		}
		time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
	}

	return v.verifyByEvidence(f)
}

func (v *VulnVerifier) replayHTTP(ctx context.Context, f *core.Finding) verifyResult {
	if v.httpClient == nil {
		return verifyDemoted
	}

	targetURL := f.Target.URL
	if targetURL == "" {
		targetURL = f.URL
	}
	if targetURL == "" {
		return verifyDemoted
	}

	reqCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", targetURL, nil)
	if err != nil {
		return verifyDemoted
	}

	body, statusCode, err := v.httpClient.Fetch(req)
	if err != nil {
		return verifyDemoted
	}

	if matchesVulnIndicators(f, body, statusCode) {
		return verifyConfirmed
	}

	return verifyDemoted
}

func (v *VulnVerifier) verifyByEvidence(f *core.Finding) verifyResult {
	if hasExploitEvidence(f) {
		return verifyConfirmed
	}
	if isVersionOnlyFinding(f) {
		return verifyDemoted
	}
	if f.Evidence != "" && len(f.Evidence) > 50 {
		return verifyConfirmed
	}
	return verifyDemoted
}

// isVersionOnlyFinding detects findings that are purely version/banner-based.
func isVersionOnlyFinding(f *core.Finding) bool {
	if f.ConfidenceReason != "" {
		lower := strings.ToLower(f.ConfidenceReason)
		if strings.Contains(lower, "version") || strings.Contains(lower, "banner") ||
			strings.Contains(lower, "cpe") || strings.Contains(lower, "版本匹配") {
			return true
		}
	}

	lower := strings.ToLower(f.Title + " " + f.Description)
	versionPatterns := []string{
		"version detected", "outdated version", "版本过旧", "版本检测",
		"known vulnerable version", "已知漏洞版本",
		"banner indicates", "banner 显示",
		"product version", "产品版本",
	}
	for _, p := range versionPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}

	if f.Data != nil {
		if _, hasVer := f.Data["version"]; hasVer {
			if _, hasProof := f.Data["proof"]; !hasProof {
				if _, hasEvidence := f.Data["evidence"]; !hasEvidence {
					if _, hasExploit := f.Data["exploit_output"]; !hasExploit {
						return true
					}
				}
			}
		}
	}

	return false
}

// hasExploitEvidence checks if a finding has actual proof of exploitation.
func hasExploitEvidence(f *core.Finding) bool {
	if f.Verified {
		return true
	}
	if f.VerificationLevel == core.VerifyExploit {
		return true
	}

	if f.Data != nil {
		exploitKeys := []string{"exploit_output", "proof", "response_match", "injection_result",
			"extracted_data", "command_output", "file_content"}
		for _, key := range exploitKeys {
			if v, ok := f.Data[key]; ok && v != "" {
				return true
			}
		}
	}

	if f.Evidence != "" {
		evidenceLower := strings.ToLower(f.Evidence)
		exploitIndicators := []string{
			"sql syntax", "syntax error", "mysql", "postgresql", "oracle",
			"<script>", "alert(", "onerror=",
			"root:", "/etc/passwd", "win.ini",
			"command output", "反射", "注入成功",
			"200 ok", "http/1.1 200",
		}
		for _, ind := range exploitIndicators {
			if strings.Contains(evidenceLower, ind) {
				return true
			}
		}
	}

	return false
}

func matchesVulnIndicators(f *core.Finding, body string, statusCode int) bool {
	if statusCode == 0 || body == "" {
		return false
	}

	fType := strings.ToLower(f.Type)
	bodyLower := strings.ToLower(body)

	switch {
	case strings.Contains(fType, "sqli") || strings.Contains(fType, "sql_injection"):
		sqlErrors := []string{
			"sql syntax", "mysql", "syntax error", "unclosed quotation",
			"postgresql", "oracle", "sqlite", "you have an error",
		}
		for _, e := range sqlErrors {
			if strings.Contains(bodyLower, e) {
				return true
			}
		}

	case strings.Contains(fType, "xss"):
		if strings.Contains(body, "<script>") || strings.Contains(body, "onerror=") ||
			strings.Contains(body, "onload=") || strings.Contains(body, "javascript:") {
			return true
		}

	case strings.Contains(fType, "lfi") || strings.Contains(fType, "file_inclusion"):
		if strings.Contains(body, "root:") || strings.Contains(body, "[boot loader]") ||
			strings.Contains(body, "[extensions]") {
			return true
		}

	case strings.Contains(fType, "ssrf"):
		if statusCode == 200 && len(body) > 100 {
			return true
		}

	case strings.Contains(fType, "info_leak") || strings.Contains(fType, "sensitive"):
		sensitivePatterns := []string{
			"password", "secret", "api_key", "private_key",
			"-----begin", "access_token",
		}
		for _, p := range sensitivePatterns {
			if strings.Contains(bodyLower, p) {
				return true
			}
		}
	}

	return false
}

func demoteSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "high"
	case "high":
		return "medium"
	case "medium":
		return "low"
	default:
		return severity
	}
}

func inferCategory(f *core.Finding) string {
	if f.Category != "" {
		return f.Category
	}
	return "recon"
}
