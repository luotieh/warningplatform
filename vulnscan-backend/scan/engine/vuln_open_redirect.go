package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type OpenRedirectScannerModule struct {
	scanner *VulnScanner
}

func NewOpenRedirectScannerModule(scanner *VulnScanner) *OpenRedirectScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "open-redirect-scanner"})
	}
	return &OpenRedirectScannerModule{scanner: scanner}
}

func (m *OpenRedirectScannerModule) ID() string       { return "open-redirect-scanner" }
func (m *OpenRedirectScannerModule) Name() string     { return "Open Redirect Scanner" }
func (m *OpenRedirectScannerModule) Category() string { return "web" }

func (m *OpenRedirectScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
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
	slog.Info("[OpenRedirect-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *OpenRedirectScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	redirectParams := []string{
		"redirect", "url", "next", "return", "returnUrl", "return_url",
		"redirect_url", "redirectUrl", "goto", "dest", "destination",
		"redir", "target", "link", "continue", "path", "forward",
	}

	maliciousURLs := []string{
		"https://evil.com",
		"//evil.com",
		"http://evil.com",
		"https://" + target.Host + ".evil.com",
		"https://evil.com?" + target.Host,
		"//evil.com/" + target.Host,
		"https:evil.com",
		"//google.com%2f%2fevil.com",
	}

	for _, param := range redirectParams {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, maliciousURL := range maliciousURLs {
			testURL := target.URL
			if strings.Contains(testURL, "?") {
				testURL += "&" + param + "=" + url.QueryEscape(maliciousURL)
			} else {
				testURL += "?" + param + "=" + url.QueryEscape(maliciousURL)
			}

			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, _, err := m.scanner.Client.FetchFull(req)
			if err != nil {
				continue
			}

			location := resp.Header.Get("Location")
			if location != "" && m.isRedirectToMalicious(location, maliciousURL) {
				findings = append(findings, &Finding{
					Target:      target,
					Type:        "open_redirect",
					Title:       "Open Redirect Vulnerability",
					Description: fmt.Sprintf("The parameter '%s' is vulnerable to open redirect. Payload: %s", param, maliciousURL),
					Severity:    "medium",
					Confidence:  85,
					Evidence:    fmt.Sprintf("GET %s redirected to %s", testURL, location),
					Timestamp:   time.Now(),
					Remediation: "Validate redirect URLs against a whitelist of allowed domains",
					Data: map[string]string{
						"param":    param,
						"payload":  maliciousURL,
						"location": location,
					},
				})

				break
			}
		}
	}

	return findings
}

func (m *OpenRedirectScannerModule) isRedirectToMalicious(location, maliciousURL string) bool {
	locationLower := strings.ToLower(location)
	maliciousLower := strings.ToLower(maliciousURL)

	if strings.Contains(locationLower, "evil.com") {
		return true
	}

	if strings.HasPrefix(locationLower, "//") && !strings.HasPrefix(maliciousLower, "http") {
		return true
	}

	return false
}
