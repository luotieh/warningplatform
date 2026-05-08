package xss

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vulnscan-backend/scan/engine"
)

type XSSScanner struct {
	base    *engine.VulnScanner
	scanCtx *engine.ScanContext
	wafEnc  *engine.WAFBypassEncoder
}

func New() *XSSScanner {
	return &XSSScanner{}
}

func (m *XSSScanner) ID() string       { return "xss" }
func (m *XSSScanner) Name() string     { return "XSS 检测" }
func (m *XSSScanner) Category() string { return "vuln" }

func (m *XSSScanner) Params() []engine.ModuleParam {
	return []engine.ModuleParam{engine.VulnVerificationParam()}
}

func (m *XSSScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	m.base = engine.NewVulnScanner(config, engine.WithTimeout(10*time.Second))
	verifyLevel := engine.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *engine.Target) []*engine.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	engine.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *XSSScanner) testTarget(ctx context.Context, target *engine.Target, verifyLevel string) []*engine.Finding {
	points := engine.ExtractInjectionPoints(target)
	if len(points) == 0 {
		parsedURL, err := url.Parse(target.URL)
		if err != nil || len(parsedURL.Query()) == 0 {
			return nil
		}
		for param := range parsedURL.Query() {
			points = append(points, engine.InjectionPoint{
				Type: engine.InjectQuery,
				Name: param,
			})
		}
	}

	var findings []*engine.Finding

	if engine.ShouldRunPrinciple(verifyLevel) {
		for _, point := range points {
			if f := m.testReflected(ctx, target, point); f != nil {
				f.VerificationLevel = engine.VerifyPrinciple
				f.VerificationDetail = "payload-reflected"
				findings = append(findings, f)
			}
		}

		if f := m.testDOMSinks(ctx, target); f != nil {
			for _, finding := range f {
				finding.VerificationLevel = engine.VerifyPrinciple
				finding.VerificationDetail = "dom-sink-detected"
			}
			findings = append(findings, f...)
		}
	}

	return findings
}

func (m *XSSScanner) testReflected(ctx context.Context, target *engine.Target, point engine.InjectionPoint) *engine.Finding {
	canary := generateCanary()

	probeBody, _, _ := m.base.SendInjected(ctx, target, point, canary)
	if !strings.Contains(probeBody, canary) {
		return nil
	}

	for _, payload := range xssPayloads(canary) {
		body, _, _ := m.base.SendInjected(ctx, target, point, payload.value)
		if body == "" {
			continue
		}

		if strings.Contains(body, payload.expect) {
			return &engine.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "xss_reflected",
				Title:       fmt.Sprintf("反射型XSS - %s: %s", point.Type, point.Name),
				Description: fmt.Sprintf("%s参数 %s 的值被直接反射到响应中且未充分编码 (context: %s)", point.Type, point.Name, payload.context),
				Severity:    "medium",
				Confidence:  80,
				Evidence:    engine.Truncate(extractContext(body, payload.expect, 200), 500),
				Timestamp:   time.Now(),
				Data: map[string]string{
					"param":      point.Name,
					"payload":    payload.value,
					"context":    payload.context,
					"type":       "reflected",
					"inject_via": string(point.Type),
				},
			}
		}
	}

	return nil
}

type xssPayload struct {
	value   string
	expect  string
	context string
}

func xssPayloads(canary string) []xssPayload {
	return []xssPayload{
		{
			value:   fmt.Sprintf(`<script>alert('%s')</script>`, canary),
			expect:  fmt.Sprintf(`<script>alert('%s')</script>`, canary),
			context: "html",
		},
		{
			value:   fmt.Sprintf(`"><img src=x onerror=alert('%s')>`, canary),
			expect:  fmt.Sprintf(`onerror=alert('%s')`, canary),
			context: "attribute",
		},
		{
			value:   fmt.Sprintf(`'><svg/onload=alert('%s')>`, canary),
			expect:  fmt.Sprintf(`onload=alert('%s')`, canary),
			context: "tag-break",
		},
		{
			value:   fmt.Sprintf(`javascript:alert('%s')`, canary),
			expect:  fmt.Sprintf(`javascript:alert('%s')`, canary),
			context: "href",
		},
		{
			value:   fmt.Sprintf(`" onfocus="alert('%s')" autofocus="`, canary),
			expect:  fmt.Sprintf(`onfocus="alert('%s')"`, canary),
			context: "event-handler",
		},
		{
			value:   fmt.Sprintf(`<details open ontoggle=alert('%s')>`, canary),
			expect:  fmt.Sprintf(`ontoggle=alert('%s')`, canary),
			context: "html5-element",
		},
		{
			value:   fmt.Sprintf(`<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert('%s') src=1>">`, canary),
			expect:  fmt.Sprintf(`onerror=alert('%s')`, canary),
			context: "mutation-xss",
		},
		{
			value:   fmt.Sprintf(`</script><script>alert('%s')</script>`, canary),
			expect:  fmt.Sprintf(`alert('%s')`, canary),
			context: "script-break",
		},
		{
			value:   fmt.Sprintf(`'-alert('%s')-'`, canary),
			expect:  fmt.Sprintf(`alert('%s')`, canary),
			context: "js-string",
		},
		{
			value:   fmt.Sprintf(`\x3cscript\x3ealert('%s')\x3c/script\x3e`, canary),
			expect:  fmt.Sprintf(`alert('%s')`, canary),
			context: "hex-encode",
		},
	}
}

var domSinkPatterns = []string{
	`document\.write\s*\(`,
	`document\.writeln\s*\(`,
	`\.innerHTML\s*=`,
	`\.outerHTML\s*=`,
	`eval\s*\(`,
	`setTimeout\s*\(\s*['"]`,
	`setInterval\s*\(\s*['"]`,
	`new\s+Function\s*\(`,
	`\.insertAdjacentHTML\s*\(`,
	`window\.location\s*=`,
	`location\.href\s*=`,
	`location\.assign\s*\(`,
	`location\.replace\s*\(`,
}

var domSourcePatterns = []string{
	`location\.hash`,
	`location\.search`,
	`location\.href`,
	`document\.URL`,
	`document\.documentURI`,
	`document\.referrer`,
	`window\.name`,
	`postMessage`,
}

func (m *XSSScanner) testDOMSinks(ctx context.Context, target *engine.Target) []*engine.Finding {
	body := m.base.FetchBody(ctx, target.URL)
	if body == "" {
		return nil
	}

	var findings []*engine.Finding
	foundSinks := map[string]bool{}
	foundSources := map[string]bool{}

	for _, pattern := range domSinkPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(body) {
			foundSinks[pattern] = true
		}
	}
	for _, pattern := range domSourcePatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(body) {
			foundSources[pattern] = true
		}
	}

	if len(foundSinks) > 0 && len(foundSources) > 0 {
		sinkList := make([]string, 0, len(foundSinks))
		for s := range foundSinks {
			sinkList = append(sinkList, s)
		}
		sourceList := make([]string, 0, len(foundSources))
		for s := range foundSources {
			sourceList = append(sourceList, s)
		}

		findings = append(findings, &engine.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "xss_dom",
			Title:       "潜在DOM XSS风险",
			Description: fmt.Sprintf("页面中同时存在DOM Source (%s) 和DOM Sink (%s)，可能存在DOM-based XSS", strings.Join(sourceList, ", "), strings.Join(sinkList, ", ")),
			Severity:    "medium",
			Confidence:  55,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"sinks":   strings.Join(sinkList, ","),
				"sources": strings.Join(sourceList, ","),
				"type":    "dom-based",
			},
		})
	}

	return findings
}

func generateCanary() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "xss" + hex.EncodeToString(b)
}

func extractContext(body, marker string, window int) string {
	idx := strings.Index(body, marker)
	if idx == -1 {
		return ""
	}

	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + len(marker) + window
	if end > len(body) {
		end = len(body)
	}

	return body[start:end]
}
