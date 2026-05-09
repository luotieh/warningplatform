package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type DeserializationScannerModule struct {
	scanner *VulnScanner
}

func NewDeserializationScannerModule(scanner *VulnScanner) *DeserializationScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "deserialization-scanner"})
	}
	return &DeserializationScannerModule{scanner: scanner}
}

func (m *DeserializationScannerModule) ID() string       { return "deserialization-scanner" }
func (m *DeserializationScannerModule) Name() string     { return "Deserialization Scanner" }
func (m *DeserializationScannerModule) Category() string { return "web" }

func (m *DeserializationScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
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
	slog.Info("[Deserialization-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *DeserializationScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	javaFindings := m.detectJavaDeserialization(ctx, target)
	findings = append(findings, javaFindings...)

	phpFindings := m.detectPHPDeserialization(ctx, target)
	findings = append(findings, phpFindings...)

	pythonFindings := m.detectPythonDeserialization(ctx, target)
	findings = append(findings, pythonFindings...)

	return findings
}

func (m *DeserializationScannerModule) detectJavaDeserialization(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	javaMagicBytes := []string{
		"rO0AB",
		"ACED0005",
	}

	for _, magic := range javaMagicBytes {
		payload := magic + strings.Repeat("A", 100)

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/x-java-serialized-object")

		body, statusCode, err := m.scanner.Client.Fetch(req)
		if err != nil {
			continue
		}

		if m.isJavaDeserializationError(statusCode, body) {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "deserialization",
				Title:       "Java Deserialization Vulnerability",
				Description: "The application appears to process Java serialized objects, which may be vulnerable to remote code execution",
				Severity:    "critical",
				Confidence:  70,
				Evidence:    fmt.Sprintf("POST %s with Java serialization header returned deserialization error", target.URL),
				Timestamp:   time.Now(),
				Remediation: "Avoid using Java native serialization, use JSON or other safe formats",
				Data: map[string]string{
					"lang":     "java",
					"magic":    magic,
					"evidence": body[:min(200, len(body))],
				},
			})
		}
	}

	return findings
}

func (m *DeserializationScannerModule) detectPHPDeserialization(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	phpPayloads := []string{
		`O:8:"stdClass":1:{s:4:"test";s:4:"data";}`,
		base64.StdEncoding.EncodeToString([]byte(`O:8:"stdClass":1:{s:4:"test";s:4:"data";}`)),
	}

	params := []string{"data", "object", "serialized", "payload", "input"}

	for _, param := range params {
		for _, payload := range phpPayloads {
			testURL := target.URL
			if strings.Contains(testURL, "?") {
				testURL += "&" + param + "=" + payload
			} else {
				testURL += "?" + param + "=" + payload
			}

			body, statusCode, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, testURL))
			if err != nil {
				continue
			}

			if m.isPHPDeserializationError(statusCode, body) {
				findings = append(findings, &Finding{
					Target:      target,
					Type:        "deserialization",
					Title:       "PHP Deserialization Vulnerability",
					Description: fmt.Sprintf("The parameter '%s' appears to process PHP serialized data", param),
					Severity:    "high",
					Confidence:  75,
					Evidence:    fmt.Sprintf("GET %s returned PHP deserialization error", testURL),
					Timestamp:   time.Now(),
					Remediation: "Use json_encode/json_decode instead of serialize/unserialize",
					Data: map[string]string{
						"lang":  "php",
						"param": param,
					},
				})
			}
		}
	}

	return findings
}

func (m *DeserializationScannerModule) detectPythonDeserialization(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	picklePayload := base64.StdEncoding.EncodeToString([]byte{
		0x80, 0x04, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	params := []string{"data", "object", "pickle", "payload"}

	for _, param := range params {
		testURL := target.URL
		if strings.Contains(testURL, "?") {
			testURL += "&" + param + "=" + picklePayload
		} else {
			testURL += "?" + param + "=" + picklePayload
		}

		body, statusCode, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, testURL))
		if err != nil {
			continue
		}

		if m.isPythonDeserializationError(statusCode, body) {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "deserialization",
				Title:       "Python Pickle Deserialization Vulnerability",
				Description: fmt.Sprintf("The parameter '%s' appears to process Python pickle data", param),
				Severity:    "critical",
				Confidence:  70,
				Evidence:    fmt.Sprintf("GET %s returned pickle deserialization error", testURL),
				Timestamp:   time.Now(),
				Remediation: "Avoid using pickle for untrusted data, use JSON instead",
				Data: map[string]string{
					"lang":  "python",
					"param": param,
				},
			})
		}
	}

	return findings
}

func (m *DeserializationScannerModule) isJavaDeserializationError(statusCode int, body string) bool {
	errorSignatures := []string{
		"InvalidClassException",
		"StreamCorruptedException",
		"OptionalDataException",
		"java.io.StreamCorruptedException",
		"ClassNotFoundException",
	}

	bodyLower := strings.ToLower(body)
	for _, sig := range errorSignatures {
		if strings.Contains(bodyLower, strings.ToLower(sig)) {
			return true
		}
	}

	return false
}

func (m *DeserializationScannerModule) isPHPDeserializationError(statusCode int, body string) bool {
	errorSignatures := []string{
		"unserialize(): Error at offset",
		"unserialize(): Unexpected end of serialized data",
		"Notice: unserialize():",
		"Warning: unserialize():",
	}

	for _, sig := range errorSignatures {
		if strings.Contains(body, sig) {
			return true
		}
	}

	return false
}

func (m *DeserializationScannerModule) isPythonDeserializationError(statusCode int, body string) bool {
	errorSignatures := []string{
		"pickle.UnpicklingError",
		"_pickle.UnpicklingError",
		"EOFError",
		"ModuleNotFoundError",
	}

	bodyLower := strings.ToLower(body)
	for _, sig := range errorSignatures {
		if strings.Contains(bodyLower, strings.ToLower(sig)) {
			return true
		}
	}

	return false
}

func (m *DeserializationScannerModule) newGetRequest(ctx context.Context, url string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return req
}
