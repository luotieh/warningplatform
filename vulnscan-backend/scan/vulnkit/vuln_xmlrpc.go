package vulnkit

import (
	"vulnscan-backend/scan/core"

	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type XMLRPCScannerModule struct {
	scanner *VulnScanner
}

func NewXMLRPCScannerModule(scanner *VulnScanner) *XMLRPCScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "xmlrpc-scanner"})
	}
	return &XMLRPCScannerModule{scanner: scanner}
}

func (m *XMLRPCScannerModule) ID() string       { return "xmlrpc-scanner" }
func (m *XMLRPCScannerModule) Name() string     { return "XML-RPC Abuse Scanner" }
func (m *XMLRPCScannerModule) Category() string { return "web" }

func (m *XMLRPCScannerModule) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
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
	slog.Info("[XMLRPC-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *XMLRPCScannerModule) scanTarget(ctx context.Context, target *core.Target) []*core.Finding {
	var findings []*core.Finding

	xmlrpcPaths := []string{
		"/xmlrpc.php",
		"/wp/xmlrpc.php",
		"/wordpress/xmlrpc.php",
	}

	for _, path := range xmlrpcPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := target.URL + path

		existsFinding := m.checkXMLRPCExists(ctx, testURL, target)
		if existsFinding == nil {
			continue
		}

		findings = append(findings, existsFinding)

		pingbackFinding := m.checkPingbackAbuse(ctx, testURL, target)
		if pingbackFinding != nil {
			findings = append(findings, pingbackFinding)
		}

		bruteFinding := m.checkBruteForce(ctx, testURL, target)
		if bruteFinding != nil {
			findings = append(findings, bruteFinding)
		}

		ddosFinding := m.checkDDoSAmp(ctx, testURL, target)
		if ddosFinding != nil {
			findings = append(findings, ddosFinding)
		}
	}

	return findings
}

func (m *XMLRPCScannerModule) checkXMLRPCExists(ctx context.Context, url string, target *core.Target) *core.Finding {
	payload := `<?xml version="1.0" encoding="utf-8"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>`

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/xml")

	respBody, statusCode, err := m.scanner.Client.Fetch(req)
	if err != nil || statusCode == http.StatusNotFound {
		return nil
	}

	if strings.Contains(respBody, "system.listMethods") ||
		strings.Contains(respBody, "methodResponse") ||
		(statusCode == http.StatusOK && strings.Contains(respBody, "xml")) {
		return &core.Finding{
			Target:      target,
			Type:        "xmlrpc_enabled",
			Title:       "XML-RPC Interface Enabled",
			Description: fmt.Sprintf("The XML-RPC interface is enabled at %s, which may be vulnerable to brute force and DDoS attacks", url),
			Severity:    "medium",
			Confidence:  90,
			Evidence:    fmt.Sprintf("POST %s returned XML-RPC response", url),
			Timestamp:   time.Now(),
			Remediation: "Disable XML-RPC if not needed, or restrict access via firewall rules",
			Data: map[string]string{
				"url": url,
			},
		}
	}

	return nil
}

func (m *XMLRPCScannerModule) checkPingbackAbuse(ctx context.Context, url string, target *core.Target) *core.Finding {
	payload := `<?xml version="1.0" encoding="utf-8"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param>
      <value><string>http://evil.com/</string></value>
    </param>
    <param>
      <value><string>` + target.URL + `/?p=1</string></value>
    </param>
  </params>
</methodCall>`

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/xml")

	respBody, statusCode, err := m.scanner.Client.Fetch(req)
	if err != nil {
		return nil
	}

	if strings.Contains(respBody, "faultCode") && strings.Contains(respBody, "faultString") {
		if strings.Contains(respBody, "404") || strings.Contains(respBody, "not found") {
			return nil
		}
	}

	if statusCode == http.StatusOK && (strings.Contains(respBody, "methodResponse") || strings.Contains(respBody, "pingback")) {
		return &core.Finding{
			Target:      target,
			Type:        "xmlrpc_pingback_abuse",
			Title:       "XML-RPC Pingback Abuse",
			Description: fmt.Sprintf("The XML-RPC pingback method at %s can be abused for DDoS attacks", url),
			Severity:    "high",
			Confidence:  80,
			Evidence:    fmt.Sprintf("POST %s with pingback payload returned success", url),
			Timestamp:   time.Now(),
			Remediation: "Disable pingback.ping method or restrict XML-RPC access",
			Data: map[string]string{
				"url": url,
			},
		}
	}

	return nil
}

func (m *XMLRPCScannerModule) checkBruteForce(ctx context.Context, url string, target *core.Target) *core.Finding {
	payload := `<?xml version="1.0" encoding="utf-8"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value>admin</value></param>
    <param><value>password</value></param>
  </params>
</methodCall>`

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/xml")

	respBody, statusCode, err := m.scanner.Client.Fetch(req)
	if err != nil {
		return nil
	}

	if statusCode == http.StatusOK && strings.Contains(respBody, "methodResponse") {
		if strings.Contains(respBody, "Incorrect username or password") ||
			strings.Contains(respBody, "faultCode") {
			return &core.Finding{
				Target:      target,
				Type:        "xmlrpc_brute_force",
				Title:       "XML-RPC Brute Force Vulnerability",
				Description: fmt.Sprintf("The XML-RPC interface at %s allows authentication attempts, enabling brute force attacks", url),
				Severity:    "high",
				Confidence:  85,
				Evidence:    fmt.Sprintf("POST %s with wp.getUsersBlogs returned authentication response", url),
				Timestamp:   time.Now(),
				Remediation: "Disable wp.getUsersBlogs method or implement rate limiting",
				Data: map[string]string{
					"url": url,
				},
			}
		}
	}

	return nil
}

func (m *XMLRPCScannerModule) checkDDoSAmp(ctx context.Context, url string, target *core.Target) *core.Finding {
	payload := `<?xml version="1.0" encoding="utf-8"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>system.listMethods</string></value>
                </member>
              </struct>
            </value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>`

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/xml")

	respBody, statusCode, err := m.scanner.Client.Fetch(req)
	if err != nil {
		return nil
	}

	if statusCode == http.StatusOK && strings.Contains(respBody, "system.multicall") {
		return &core.Finding{
			Target:      target,
			Type:        "xmlrpc_ddos_amp",
			Title:       "XML-RPC DDoS Amplification",
			Description: fmt.Sprintf("The XML-RPC system.multicall method at %s can be used for DDoS amplification", url),
			Severity:    "high",
			Confidence:  80,
			Evidence:    fmt.Sprintf("POST %s with system.multicall returned success", url),
			Timestamp:   time.Now(),
			Remediation: "Disable system.multicall method or restrict XML-RPC access",
			Data: map[string]string{
				"url": url,
			},
		}
	}

	return nil
}
