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

type CORSScannerModule struct {
	scanner *VulnScanner
}

func NewCORSScannerModule(scanner *VulnScanner) *CORSScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "cors-scanner"})
	}
	return &CORSScannerModule{scanner: scanner}
}

func (m *CORSScannerModule) ID() string       { return "cors-scanner" }
func (m *CORSScannerModule) Name() string     { return "CORS Scanner" }
func (m *CORSScannerModule) Category() string { return "web" }

func (m *CORSScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
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
	slog.Info("[CORS-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *CORSScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	origins := []string{
		"https://evil.com",
		"null",
		"https://" + target.Host + ".evil.com",
	}

	for _, origin := range origins {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
		req.Header.Set("Origin", origin)

		resp, _, err := m.scanner.Client.FetchFull(req)
		if err != nil {
			continue
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == origin || (acao == "*" && acac == "true") {
			severity := "medium"
			confidence := 70
			title := "CORS Misconfiguration"
			desc := fmt.Sprintf("The server reflects the Origin header '%s' in Access-Control-Allow-Origin", origin)

			if acao == origin && acac == "true" {
				severity = "high"
				confidence = 85
				title = "CORS Misconfiguration with Credentials"
				desc = fmt.Sprintf("The server allows cross-origin requests from '%s' with credentials", origin)
			}

			if origin == "null" && acao == "null" {
				severity = "medium"
				confidence = 75
				title = "CORS Allows Null Origin"
				desc = "The server allows requests from null origin (sandboxed iframe)"
			}

			findings = append(findings, &Finding{
				Target:      target,
				Type:        "cors",
				Title:       title,
				Description: desc,
				Severity:    severity,
				Confidence:  confidence,
				Evidence:    fmt.Sprintf("Origin: %s -> Access-Control-Allow-Origin: %s, Credentials: %s", origin, acao, acac),
				Timestamp:   time.Now(),
				Remediation: "Configure strict CORS policy, avoid wildcard origins with credentials",
				Data: map[string]string{
					"origin":      origin,
					"acao":        acao,
					"credentials": acac,
				},
			})
		}
	}

	if len(findings) == 0 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
		resp, _, err := m.scanner.Client.FetchFull(req)
		if err == nil {
			acao := resp.Header.Get("Access-Control-Allow-Origin")
			if acao == "*" {
				findings = append(findings, &Finding{
					Target:      target,
					Type:        "cors",
					Title:       "CORS Allows All Origins",
					Description: "The server allows cross-origin requests from any origin",
					Severity:    "low",
					Confidence:  90,
					Evidence:    "Access-Control-Allow-Origin: *",
					Timestamp:   time.Now(),
					Remediation: "Restrict CORS to trusted origins",
					Data: map[string]string{
						"acao": acao,
					},
				})
			}
		}
	}

	return findings
}

func (m *CORSScannerModule) detectCORSMethods(ctx context.Context, target *Target) []string {
	req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, target.URL, nil)
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, _, err := m.scanner.Client.FetchFull(req)
	if err != nil {
		return nil
	}

	acam := resp.Header.Get("Access-Control-Allow-Methods")
	if acam != "" {
		return strings.Split(acam, ",")
	}

	return nil
}
