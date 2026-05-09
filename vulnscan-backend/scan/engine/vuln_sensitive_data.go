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

type SensitiveDataScannerModule struct {
	scanner *VulnScanner
}

func NewSensitiveDataScannerModule(scanner *VulnScanner) *SensitiveDataScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "sensitive-data-scanner"})
	}
	return &SensitiveDataScannerModule{scanner: scanner}
}

func (m *SensitiveDataScannerModule) ID() string       { return "sensitive-data-scanner" }
func (m *SensitiveDataScannerModule) Name() string     { return "Sensitive Data Exposure Scanner" }
func (m *SensitiveDataScannerModule) Category() string { return "web" }

func (m *SensitiveDataScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
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
	slog.Info("[SensitiveData-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *SensitiveDataScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	apiEndpoints := []string{
		"/api/users",
		"/api/profile",
		"/api/account",
		"/api/settings",
		"/api/admin/users",
		"/api/v1/users",
		"/api/v2/users",
	}

	for _, endpoint := range apiEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := target.URL + endpoint
		body, statusCode, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, testURL))
		if err != nil || statusCode != http.StatusOK {
			continue
		}

		sensitiveData := m.detectSensitiveData(body)
		if len(sensitiveData) > 0 {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "sensitive_data_exposure",
				Title:       "Sensitive Data Exposure in API Response",
				Description: fmt.Sprintf("The endpoint %s exposes sensitive data: %s", endpoint, strings.Join(sensitiveData, ", ")),
				Severity:    "high",
				Confidence:  80,
				Evidence:    fmt.Sprintf("GET %s returned sensitive data", testURL),
				Timestamp:   time.Now(),
				Remediation: "Remove sensitive fields from API responses, implement data filtering",
				Data: map[string]string{
					"endpoint":       endpoint,
					"sensitive_data": strings.Join(sensitiveData, ", "),
				},
			})
		}
	}

	return findings
}

func (m *SensitiveDataScannerModule) detectSensitiveData(body string) []string {
	var found []string

	patterns := map[string]*regexp.Regexp{
		"id_card":       regexp.MustCompile(`\b\d{17}[\dXx]\b`),
		"phone_number":  regexp.MustCompile(`\b1[3-9]\d{9}\b`),
		"email":         regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
		"bank_card":     regexp.MustCompile(`\b\d{16,19}\b`),
		"password_hash": regexp.MustCompile(`\b[a-f0-9]{32,64}\b`),
		"jwt_token":     regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		"api_key":       regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?[A-Za-z0-9]{16,}['"]?`),
		"secret_key":    regexp.MustCompile(`(?i)(secret[_-]?key|secret)\s*[:=]\s*['"]?[A-Za-z0-9]{16,}['"]?`),
		"access_token":  regexp.MustCompile(`(?i)(access[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_.-]{16,}['"]?`),
		"private_key":   regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`),
	}

	for dataType, pattern := range patterns {
		if pattern.MatchString(body) {
			found = append(found, dataType)
		}
	}

	return found
}

func (m *SensitiveDataScannerModule) newGetRequest(ctx context.Context, url string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return req
}
