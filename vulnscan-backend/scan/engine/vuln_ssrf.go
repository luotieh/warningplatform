package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SSRFScannerModule struct {
	scanner *VulnScanner
}

func NewSSRFScannerModule(scanner *VulnScanner) *SSRFScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "ssrf-scanner"})
	}
	return &SSRFScannerModule{scanner: scanner}
}

func (m *SSRFScannerModule) ID() string       { return "ssrf-scanner" }
func (m *SSRFScannerModule) Name() string     { return "SSRF Scanner" }
func (m *SSRFScannerModule) Category() string { return "web" }

func (m *SSRFScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
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
	slog.Info("[SSRF-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *SSRFScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	ssrfParams := []string{"url", "dest", "redirect", "uri", "path", "continue", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir", "show", "navigation", "open"}

	for _, param := range ssrfParams {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		payloads := []struct {
			payload  string
			evidence string
		}{
			{"http://127.0.0.1", "localhost"},
			{"http://localhost", "localhost"},
			{"http://0.0.0.0", "0.0.0.0"},
			{"http://169.254.169.254/latest/meta-data/", "ami-id"},
			{"http://[::1]", "::1"},
		}

		for _, p := range payloads {
			testURL := target.URL
			if strings.Contains(testURL, "?") {
				testURL += "&" + param + "=" + p.payload
			} else {
				testURL += "?" + param + "=" + p.payload
			}

			body, statusCode, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, testURL))
			if err != nil {
				continue
			}

			if statusCode == http.StatusOK && len(body) > 0 {
				if strings.Contains(strings.ToLower(body), p.evidence) ||
					strings.Contains(body, "root:x:0:0") ||
					strings.Contains(body, "ami-id") {
					findings = append(findings, &Finding{
						Target:      target,
						Type:        "ssrf",
						Title:       "Server-Side Request Forgery (SSRF)",
						Description: fmt.Sprintf("The parameter '%s' is vulnerable to SSRF. Payload: %s", param, p.payload),
						Severity:    "high",
						Confidence:  75,
						Evidence:    fmt.Sprintf("GET %s returned evidence of internal access", testURL),
						Timestamp:   time.Now(),
						Remediation: "Validate and whitelist allowed URLs, implement URL scheme validation",
						Data: map[string]string{
							"param":   param,
							"payload": p.payload,
						},
					})
				}
			}
		}
	}

	return findings
}

func (m *SSRFScannerModule) newGetRequest(ctx context.Context, url string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return req
}
