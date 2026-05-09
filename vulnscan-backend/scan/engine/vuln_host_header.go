package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/pkg/payload"
)

type HostHeaderScannerModule struct {
	scanner  *VulnScanner
	payloads *payload.Loader
}

func NewHostHeaderScannerModule(scanner *VulnScanner, loader *payload.Loader) *HostHeaderScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "host-header-scanner"})
	}
	return &HostHeaderScannerModule{scanner: scanner, payloads: loader}
}

func (m *HostHeaderScannerModule) ID() string       { return "host-header-scanner" }
func (m *HostHeaderScannerModule) Name() string     { return "Host Header Injection Scanner" }
func (m *HostHeaderScannerModule) Category() string { return "web" }

func (m *HostHeaderScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
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
	slog.Info("[HostHeader-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *HostHeaderScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	maliciousHosts := m.getHostHeaderPayloads(target.Host)

	for _, maliciousHost := range maliciousHosts {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
		req.Host = maliciousHost

		resp, body, err := m.scanner.Client.FetchFull(req)
		if err != nil {
			continue
		}

		location := resp.Header.Get("Location")
		if strings.Contains(location, maliciousHost) {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "host_header_injection",
				Title:       "Host Header Injection",
				Description: fmt.Sprintf("The application uses the Host header to construct redirect URLs, allowing injection of '%s'", maliciousHost),
				Severity:    "high",
				Confidence:  85,
				Evidence:    fmt.Sprintf("Host: %s -> Location: %s", maliciousHost, location),
				Timestamp:   time.Now(),
				Remediation: "Use a whitelist of allowed hostnames, do not trust the Host header",
				Data: map[string]string{
					"host":     maliciousHost,
					"location": location,
				},
			})

			break
		}

		if strings.Contains(body, maliciousHost) {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "host_header_injection",
				Title:       "Host Header Injection (Reflected)",
				Description: fmt.Sprintf("The application reflects the malicious Host header '%s' in the response", maliciousHost),
				Severity:    "medium",
				Confidence:  75,
				Evidence:    fmt.Sprintf("Host: %s reflected in response body", maliciousHost),
				Timestamp:   time.Now(),
				Remediation: "Use a whitelist of allowed hostnames, do not trust the Host header",
				Data: map[string]string{
					"host": maliciousHost,
				},
			})

			break
		}
	}

	return findings
}

func (m *HostHeaderScannerModule) getHostHeaderPayloads(host string) []string {
	if m.payloads != nil {
		cfg := m.payloads.GetHostHeader()
		if cfg != nil && len(cfg.Payloads) > 0 {
			var result []string
			for _, p := range cfg.Payloads {
				value := strings.ReplaceAll(p.Value, "{host}", host)
				result = append(result, value)
			}
			return result
		}
	}
	return defaultHostHeaderPayloads(host)
}

func defaultHostHeaderPayloads(host string) []string {
	return []string{
		"evil.com",
		"attacker.com",
		host + ".evil.com",
		"evil.com/" + host,
		"evil.com:80",
	}
}
