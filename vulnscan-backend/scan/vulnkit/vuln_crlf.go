package vulnkit

import (
	"vulnscan-backend/scan/core"

	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/pkg/payload"
)

type CRLFScannerModule struct {
	scanner  *VulnScanner
	payloads *payload.Loader
}

func NewCRLFScannerModule(scanner *VulnScanner, loader *payload.Loader) *CRLFScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "crlf-scanner"})
	}
	return &CRLFScannerModule{scanner: scanner, payloads: loader}
}

func (m *CRLFScannerModule) ID() string       { return "crlf-scanner" }
func (m *CRLFScannerModule) Name() string     { return "CRLF Injection Scanner" }
func (m *CRLFScannerModule) Category() string { return "web" }

func (m *CRLFScannerModule) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}
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
		go func(t *core.Target) {
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
	slog.Info("[CRLF-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *CRLFScannerModule) scanTarget(ctx context.Context, target *core.Target) []*core.Finding {
	var findings []*core.Finding

	params := m.getCRLFParams()
	payloads := m.getCRLFPayloads()

	for _, param := range params {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, p := range payloads {
			testURL := target.URL
			if strings.Contains(testURL, "?") {
				testURL += "&" + param + "=" + p.Value
			} else {
				testURL += "?" + param + "=" + p.Value
			}

			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
			resp, _, err := m.scanner.Client.FetchFull(req)
			if err != nil {
				continue
			}

			if resp.Header.Get("Crlf-Inject") == "test" || resp.Header.Get("X-CRLF-Injected") == "true" {
				findings = append(findings, &core.Finding{
					Target:      target,
					Type:        "crlf_injection",
					Title:       "CRLF Injection Vulnerability",
					Description: fmt.Sprintf("The parameter '%s' is vulnerable to CRLF injection. Payload: %s", param, p.Value),
					Severity:    "high",
					Confidence:  90,
					Evidence:    fmt.Sprintf("GET %s injected custom header", testURL),
					Timestamp:   time.Now(),
					Remediation: "Encode CRLF characters in user input before using in HTTP headers",
					Data: map[string]string{
						"param":   param,
						"payload": p.Value,
					},
				})

				break
			}
		}
	}

	return findings
}

func (m *CRLFScannerModule) getCRLFParams() []string {
	if m.payloads != nil {
		cfg := m.payloads.GetCRLF()
		if cfg != nil && len(cfg.Params) > 0 {
			return cfg.Params
		}
	}
	return defaultCRLFParams()
}

func (m *CRLFScannerModule) getCRLFPayloads() []payload.PayloadEntry {
	if m.payloads != nil {
		cfg := m.payloads.GetCRLF()
		if cfg != nil && len(cfg.Payloads) > 0 {
			return cfg.Payloads
		}
	}
	return defaultCRLFPayloads()
}

func defaultCRLFParams() []string {
	return []string{
		"redirect", "url", "next", "return", "returnUrl", "return_url",
		"redirect_url", "redirectUrl", "goto", "dest", "destination",
		"redir", "target", "link", "continue", "path", "forward",
		"uri", "page", "ref", "referer",
	}
}

func defaultCRLFPayloads() []payload.PayloadEntry {
	return []payload.PayloadEntry{
		{Value: "%0d%0aSet-Cookie:crlf_inject=test"},
		{Value: "%0d%0aX-CRLF-Injected:true"},
		{Value: "%0a%0dSet-Cookie:crlf_inject=test"},
		{Value: "%250a%250dSet-Cookie:crlf_inject=test"},
		{Value: "%E5%98%8A%E5%98%8DSet-Cookie:crlf_inject=test"},
	}
}
