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

type WebScannerModule struct {
	scanner *VulnScanner
}

func NewWebScannerModule(scanner *VulnScanner) *WebScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "web-scanner"})
	}
	return &WebScannerModule{scanner: scanner}
}

func (m *WebScannerModule) ID() string       { return "web-scanner" }
func (m *WebScannerModule) Name() string     { return "Web Application Scanner" }
func (m *WebScannerModule) Category() string { return "web" }

func (m *WebScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	start := time.Now()
	result := &ModuleResult{ModuleID: m.ID()}

	for _, target := range targets {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		if target.URL == "" && target.Host != "" {
			target.URL = fmt.Sprintf("http://%s", target.Host)
			if target.Port == 443 || target.Protocol == "https" {
				target.URL = fmt.Sprintf("https://%s", target.Host)
			}
		}

		findings := m.scanTarget(ctx, target)
		result.Findings = append(result.Findings, findings...)
	}

	result.Duration = time.Since(start)
	slog.Info("[Web-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *WebScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	findings = append(findings, m.checkSecurityHeaders(ctx, target)...)
	findings = append(findings, m.checkHTTPMethods(ctx, target)...)
	findings = append(findings, m.checkInformationDisclosure(ctx, target)...)
	findings = append(findings, m.checkDefaultPages(ctx, target)...)

	return findings
}

func (m *WebScannerModule) checkSecurityHeaders(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	resp, body, err := m.scanner.Client.FetchFull(m.newGetRequest(ctx, target.URL))
	if err != nil || resp == nil {
		return findings
	}

	securityHeaders := map[string]struct {
		name        string
		description string
		severity    string
	}{
		"Strict-Transport-Security": {
			"Missing HSTS Header",
			"HTTP Strict Transport Security header is not set, making the site vulnerable to protocol downgrade attacks",
			"medium",
		},
		"X-Content-Type-Options": {
			"Missing X-Content-Type-Options Header",
			"X-Content-Type-Options: nosniff header is not set, browser may MIME-sniff responses",
			"low",
		},
		"X-Frame-Options": {
			"Missing X-Frame-Options Header",
			"X-Frame-Options header is not set, page may be vulnerable to clickjacking",
			"medium",
		},
		"Content-Security-Policy": {
			"Missing Content-Security-Policy Header",
			"Content-Security-Policy header is not set, page may be vulnerable to XSS and data injection",
			"medium",
		},
		"X-XSS-Protection": {
			"Missing X-XSS-Protection Header",
			"X-XSS-Protection header is not set, browser XSS filter may not be enabled",
			"low",
		},
		"Referrer-Policy": {
			"Missing Referrer-Policy Header",
			"Referrer-Policy header is not set, referrer information may be leaked",
			"low",
		},
	}

	for header, info := range securityHeaders {
		if resp.Header.Get(header) == "" {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "security_header",
				Title:       info.name,
				Description: info.description,
				Severity:    info.severity,
				Confidence:  90,
				Evidence:    fmt.Sprintf("Response headers do not include: %s", header),
				Timestamp:   time.Now(),
				Remediation: fmt.Sprintf("Add %s header to all HTTP responses", header),
			})
		}
	}

	if strings.Contains(strings.ToLower(body), "<!--") {
		findings = append(findings, &Finding{
			Target:      target,
			Type:        "info_disclosure",
			Title:       "HTML Comments Found",
			Description: "HTML comments may contain sensitive information or internal notes",
			Severity:    "info",
			Confidence:  60,
			Evidence:    "Response body contains HTML comments",
			Timestamp:   time.Now(),
			Remediation: "Remove unnecessary HTML comments from production code",
		})
	}

	return findings
}

func (m *WebScannerModule) checkHTTPMethods(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	dangerousMethods := []string{"TRACE", "DELETE", "PUT", "PATCH"}

	for _, method := range dangerousMethods {
		req, err := http.NewRequestWithContext(ctx, method, target.URL, nil)
		if err != nil {
			continue
		}

		_, statusCode, err := m.scanner.Client.Fetch(req)
		if err != nil {
			continue
		}

		if statusCode != http.StatusMethodNotAllowed && statusCode != http.StatusNotFound {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "http_method",
				Title:       fmt.Sprintf("Dangerous HTTP Method Enabled: %s", method),
				Description: fmt.Sprintf("The server accepts %s requests which may allow information disclosure or unauthorized actions", method),
				Severity:    "medium",
				Confidence:  70,
				Evidence:    fmt.Sprintf("%s request returned status %d", method, statusCode),
				Timestamp:   time.Now(),
				Remediation: fmt.Sprintf("Disable %s HTTP method if not required", method),
			})
		}
	}

	return findings
}

func (m *WebScannerModule) checkInformationDisclosure(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	sensitivePaths := map[string]struct {
		title       string
		description string
		severity    string
	}{
		"/.env": {
			"Environment File Exposed",
			"The .env file is publicly accessible and may contain database credentials, API keys, and other secrets",
			"critical",
		},
		"/.git/config": {
			"Git Configuration Exposed",
			"The .git/config file is accessible, potentially exposing repository information",
			"high",
		},
		"/.git/HEAD": {
			"Git HEAD Exposed",
			"The .git/HEAD file is accessible, indicating the .git directory may be exposed",
			"high",
		},
		"/server-status": {
			"Server Status Page Exposed",
			"The Apache server-status page is publicly accessible",
			"medium",
		},
		"/phpinfo.php": {
			"PHP Info Page Exposed",
			"The phpinfo.php page is publicly accessible, exposing server configuration details",
			"high",
		},
		"/actuator/env": {
			"Spring Actuator Env Exposed",
			"The Spring Boot Actuator /env endpoint is publicly accessible",
			"high",
		},
		"/actuator/health": {
			"Spring Actuator Health Exposed",
			"The Spring Boot Actuator /health endpoint is publicly accessible",
			"low",
		},
		"/wp-config.php.bak": {
			"WordPress Config Backup Exposed",
			"A backup of wp-config.php is publicly accessible, potentially exposing database credentials",
			"critical",
		},
		"/debug/pprof": {
			"Go Pprof Endpoint Exposed",
			"The Go pprof debugging endpoint is publicly accessible",
			"high",
		},
		"/swagger.json": {
			"Swagger API Documentation Exposed",
			"The Swagger API documentation is publicly accessible",
			"low",
		},
	}

	baseURL := strings.TrimRight(target.URL, "/")
	sem := make(chan struct{}, 5)

	for path, info := range sensitivePaths {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string, inf struct {
			title       string
			description string
			severity    string
		}) {
			defer wg.Done()
			defer func() { <-sem }()

			body, statusCode, _ := m.scanner.Client.Fetch(m.newGetRequest(ctx, baseURL+p))
			if statusCode == http.StatusOK && len(body) > 0 {
				finding := &Finding{
					Target:      target,
					Type:        "info_disclosure",
					Title:       inf.title,
					Description: inf.description,
					Severity:    inf.severity,
					Confidence:  85,
					Evidence:    fmt.Sprintf("GET %s returned status %d with %d bytes", p, statusCode, len(body)),
					Timestamp:   time.Now(),
					Remediation: fmt.Sprintf("Restrict access to %s or remove it from the web root", p),
				}
				mu.Lock()
				findings = append(findings, finding)
				mu.Unlock()
			}
		}(path, info)
	}

	wg.Wait()
	return findings
}

func (m *WebScannerModule) checkDefaultPages(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	defaultPages := map[string]struct {
		title    string
		severity string
	}{
		"/admin": {
			"Admin Panel Accessible",
			"medium",
		},
		"/login": {
			"Login Page Found",
			"info",
		},
		"/api": {
			"API Endpoint Found",
			"info",
		},
	}

	baseURL := strings.TrimRight(target.URL, "/")

	for path, info := range defaultPages {
		_, statusCode, _ := m.scanner.Client.Fetch(m.newGetRequest(ctx, baseURL+path))
		if statusCode != http.StatusNotFound {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "discovery",
				Title:       info.title,
				Description: fmt.Sprintf("Default page found at %s", path),
				Severity:    info.severity,
				Confidence:  70,
				Evidence:    fmt.Sprintf("GET %s returned status %d", path, statusCode),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

func (m *WebScannerModule) newGetRequest(ctx context.Context, url string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return req
}
