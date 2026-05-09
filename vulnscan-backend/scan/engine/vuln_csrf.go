package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type CSRFScannerModule struct {
	scanner *VulnScanner
}

func NewCSRFScannerModule(scanner *VulnScanner) *CSRFScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "csrf-scanner"})
	}
	return &CSRFScannerModule{scanner: scanner}
}

func (m *CSRFScannerModule) ID() string       { return "csrf-scanner" }
func (m *CSRFScannerModule) Name() string     { return "CSRF Scanner" }
func (m *CSRFScannerModule) Category() string { return "web" }

func (m *CSRFScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	start := time.Now()
	result := &ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 5)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		if target.URL == "" && target.Host != "" {
			target.URL = fmt.Sprintf("http://%s", target.Host)
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t *Target) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := m.scanTarget(ctx, t)
			if len(findings) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	slog.Info("[CSRF-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *CSRFScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	body, statusCode, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, target.URL))
	if err != nil || statusCode != http.StatusOK {
		return findings
	}

	if !hasStateChangingForm(body) {
		return findings
	}

	csrfTokens := extractCSRFTokenNames(body)
	if len(csrfTokens) == 0 {
		findings = append(findings, &Finding{
			Target:      target,
			Type:        "csrf",
			Title:       "Missing CSRF Protection",
			Description: "The page contains state-changing forms without CSRF token protection",
			Severity:    "medium",
			Confidence:  70,
			Evidence:    fmt.Sprintf("Forms found without CSRF tokens on %s", target.URL),
			Timestamp:   time.Now(),
			Remediation: "Implement CSRF tokens for all state-changing forms",
			Data: map[string]string{
				"url": target.URL,
			},
		})
	}

	if !hasSameSiteCookie(ctx, m.scanner, target.URL) {
		findings = append(findings, &Finding{
			Target:      target,
			Type:        "csrf",
			Title:       "Missing SameSite Cookie Attribute",
			Description: "Session cookies do not have SameSite attribute set, making CSRF attacks possible",
			Severity:    "low",
			Confidence:  75,
			Evidence:    "No SameSite attribute found in Set-Cookie headers",
			Timestamp:   time.Now(),
			Remediation: "Set SameSite=Strict or SameSite=Lax on session cookies",
			Data: map[string]string{
				"url": target.URL,
			},
		})
	}

	return findings
}

func hasStateChangingForm(body string) bool {
	formPatterns := []string{
		`<form[^>]*method=["']post["']`,
		`<form[^>]*method=["']PUT["']`,
		`<form[^>]*method=["']DELETE["']`,
		`<form[^>]*method=["']PATCH["']`,
	}

	for _, pattern := range formPatterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			return true
		}
	}

	return false
}

func extractCSRFTokenNames(body string) []string {
	tokenNames := []string{
		"csrf_token", "csrf", "_token", "authenticity_token",
		"xsrf_token", "_xsrf", "csrfmiddlewaretoken",
	}

	var found []string
	for _, name := range tokenNames {
		pattern := fmt.Sprintf(`name=["'][^"]*%s[^"]*["']`, name)
		if matched, _ := regexp.MatchString(pattern, body); matched {
			found = append(found, name)
		}
	}

	return found
}

func hasSameSiteCookie(ctx context.Context, scanner *VulnScanner, url string) bool {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, _, err := scanner.Client.FetchFull(req)
	if err != nil {
		return false
	}

	for _, cookie := range resp.Cookies() {
		if strings.Contains(strings.ToLower(cookie.String()), "samesite") {
			return true
		}
	}

	return false
}

func (m *CSRFScannerModule) newGetRequest(ctx context.Context, url string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return req
}
