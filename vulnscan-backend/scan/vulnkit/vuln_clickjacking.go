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
)

type ClickjackingScannerModule struct {
	scanner *VulnScanner
}

func NewClickjackingScannerModule(scanner *VulnScanner) *ClickjackingScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "clickjacking-scanner"})
	}
	return &ClickjackingScannerModule{scanner: scanner}
}

func (m *ClickjackingScannerModule) ID() string       { return "clickjacking-scanner" }
func (m *ClickjackingScannerModule) Name() string     { return "Clickjacking Scanner" }
func (m *ClickjackingScannerModule) Category() string { return "web" }

func (m *ClickjackingScannerModule) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 10)

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

			finding := m.scanTarget(ctx, t)
			if finding != nil {
				mu.Lock()
				result.Findings = append(result.Findings, finding)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	slog.Info("[Clickjacking-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *ClickjackingScannerModule) scanTarget(ctx context.Context, target *core.Target) *core.Finding {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	resp, _, err := m.scanner.Client.FetchFull(req)
	if err != nil {
		return nil
	}

	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")

	hasXFO := xfo != ""
	hasCSPFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")

	if !hasXFO && !hasCSPFrameAncestors {
		return &core.Finding{
			Target:      target,
			Type:        "clickjacking",
			Title:       "Missing Clickjacking Protection",
			Description: "The page does not have X-Frame-Options or Content-Security-Policy frame-ancestors header set",
			Severity:    "medium",
			Confidence:  90,
			Evidence:    "No X-Frame-Options or CSP frame-ancestors header found",
			Timestamp:   time.Now(),
			Remediation: "Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors directive",
			Data: map[string]string{
				"xfo": xfo,
				"csp": csp,
			},
		}
	}

	if hasXFO && !isValidXFO(xfo) {
		return &core.Finding{
			Target:      target,
			Type:        "clickjacking",
			Title:       "Weak X-Frame-Options Configuration",
			Description: fmt.Sprintf("The X-Frame-Options header is set to '%s' which may allow clickjacking", xfo),
			Severity:    "low",
			Confidence:  80,
			Evidence:    fmt.Sprintf("X-Frame-Options: %s", xfo),
			Timestamp:   time.Now(),
			Remediation: "Set X-Frame-Options to DENY or SAMEORIGIN",
			Data: map[string]string{
				"xfo": xfo,
			},
		}
	}

	return nil
}

func isValidXFO(xfo string) bool {
	xfoUpper := strings.ToUpper(strings.TrimSpace(xfo))
	return xfoUpper == "DENY" || xfoUpper == "SAMEORIGIN"
}
