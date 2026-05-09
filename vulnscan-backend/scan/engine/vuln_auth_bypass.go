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

type AuthBypassScannerModule struct {
	scanner *VulnScanner
}

func NewAuthBypassScannerModule(scanner *VulnScanner) *AuthBypassScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "auth-bypass-scanner"})
	}
	return &AuthBypassScannerModule{scanner: scanner}
}

func (m *AuthBypassScannerModule) ID() string       { return "auth-bypass-scanner" }
func (m *AuthBypassScannerModule) Name() string     { return "Auth Bypass Scanner" }
func (m *AuthBypassScannerModule) Category() string { return "web" }

func (m *AuthBypassScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	start := time.Now()
	result := &ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 3)

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
	slog.Info("[AuthBypass-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *AuthBypassScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	protectedPaths := []string{
		"/admin",
		"/dashboard",
		"/api/users",
		"/api/admin",
		"/profile",
		"/settings",
		"/account",
	}

	for _, path := range protectedPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := target.URL + path

		bypassTechniques := []func(context.Context, string) *Finding{
			func(ctx context.Context, url string) *Finding {
				return m.testHTTPMethodBypass(ctx, url)
			},
			func(ctx context.Context, url string) *Finding {
				return m.testPathTraversalBypass(ctx, url)
			},
			func(ctx context.Context, url string) *Finding {
				return m.testHeaderBypass(ctx, url)
			},
			func(ctx context.Context, url string) *Finding {
				return m.testNullByteBypass(ctx, url)
			},
		}

		for _, technique := range bypassTechniques {
			finding := technique(ctx, testURL)
			if finding != nil {
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (m *AuthBypassScannerModule) testHTTPMethodBypass(ctx context.Context, url string) *Finding {
	bypassMethods := []string{"OPTIONS", "HEAD", "TRACE", "PATCH"}

	for _, method := range bypassMethods {
		req, _ := http.NewRequestWithContext(ctx, method, url, nil)
		body, statusCode, err := m.scanner.Client.Fetch(req)
		if err != nil {
			continue
		}

		if statusCode == http.StatusOK && !isLoginPage(body) {
			return &Finding{
				Target:      nil,
				Type:        "auth_bypass",
				Title:       "Authentication Bypass via HTTP Method",
				Description: fmt.Sprintf("The endpoint %s can be accessed using %s method without authentication", url, method),
				Severity:    "high",
				Confidence:  70,
				Evidence:    fmt.Sprintf("%s %s returned 200 OK", method, url),
				Timestamp:   time.Now(),
				Remediation: "Enforce authentication for all HTTP methods",
				Data: map[string]string{
					"method": method,
					"url":    url,
				},
			}
		}
	}

	return nil
}

func (m *AuthBypassScannerModule) testPathTraversalBypass(ctx context.Context, url string) *Finding {
	bypassPaths := []string{
		url + "/..;/",
		url + ";/",
		url + "/%2e%2e/",
		url + "/./",
		url + "//",
	}

	for _, bypassURL := range bypassPaths {
		body, statusCode, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, bypassURL))
		if err != nil {
			continue
		}

		if statusCode == http.StatusOK && !isLoginPage(body) {
			return &Finding{
				Target:      nil,
				Type:        "auth_bypass",
				Title:       "Authentication Bypass via Path Manipulation",
				Description: fmt.Sprintf("The endpoint %s can be bypassed using path manipulation", url),
				Severity:    "high",
				Confidence:  75,
				Evidence:    fmt.Sprintf("GET %s returned 200 OK", bypassURL),
				Timestamp:   time.Now(),
				Remediation: "Normalize paths before authentication check",
				Data: map[string]string{
					"url": bypassURL,
				},
			}
		}
	}

	return nil
}

func (m *AuthBypassScannerModule) testHeaderBypass(ctx context.Context, url string) *Finding {
	bypassHeaders := []map[string]string{
		{"X-Original-URL": url},
		{"X-Rewrite-URL": url},
		{"X-Forwarded-For": "127.0.0.1"},
		{"X-Forwarded-Host": "127.0.0.1"},
		{"X-Remote-IP": "127.0.0.1"},
		{"X-Client-IP": "127.0.0.1"},
		{"X-Host": "127.0.0.1"},
	}

	for _, headers := range bypassHeaders {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+"/", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		body, statusCode, err := m.scanner.Client.Fetch(req)
		if err != nil {
			continue
		}

		if statusCode == http.StatusOK && !isLoginPage(body) {
			return &Finding{
				Target:      nil,
				Type:        "auth_bypass",
				Title:       "Authentication Bypass via HTTP Header",
				Description: fmt.Sprintf("The endpoint %s can be bypassed using custom headers", url),
				Severity:    "high",
				Confidence:  70,
				Evidence:    fmt.Sprintf("GET %s with headers %v returned 200 OK", url, headers),
				Timestamp:   time.Now(),
				Remediation: "Do not trust client-supplied headers for access control",
				Data: map[string]string{
					"url":     url,
					"headers": fmt.Sprintf("%v", headers),
				},
			}
		}
	}

	return nil
}

func (m *AuthBypassScannerModule) testNullByteBypass(ctx context.Context, url string) *Finding {
	nullByteURLs := []string{
		url + "%00",
		url + "%0a",
		url + "%0d",
		url + "%20",
	}

	for _, nullURL := range nullByteURLs {
		body, statusCode, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, nullURL))
		if err != nil {
			continue
		}

		if statusCode == http.StatusOK && !isLoginPage(body) {
			return &Finding{
				Target:      nil,
				Type:        "auth_bypass",
				Title:       "Authentication Bypass via Null Byte",
				Description: fmt.Sprintf("The endpoint %s can be bypassed using null byte injection", url),
				Severity:    "high",
				Confidence:  65,
				Evidence:    fmt.Sprintf("GET %s returned 200 OK", nullURL),
				Timestamp:   time.Now(),
				Remediation: "Sanitize input and reject null bytes",
				Data: map[string]string{
					"url": nullURL,
				},
			}
		}
	}

	return nil
}

func isLoginPage(body string) bool {
	loginIndicators := []string{
		"login",
		"sign in",
		"sign-in",
		"signin",
		"username",
		"password",
		"authentication",
		"401",
		"403",
		"unauthorized",
		"forbidden",
		"access denied",
	}

	bodyLower := strings.ToLower(body)
	for _, indicator := range loginIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}

	return false
}

func (m *AuthBypassScannerModule) newGetRequest(ctx context.Context, url string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return req
}
