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

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/engine"
)

type XSSScanner struct {
	base     *engine.VulnScanner
	scanCtx  *engine.ScanContext
	wafEnc   *engine.WAFBypassEncoder
	payloads *payload.Loader
}

func New(loader *payload.Loader) *XSSScanner {
	return &XSSScanner{payloads: loader}
}

func (m *XSSScanner) ID() string       { return "xss" }
func (m *XSSScanner) Name() string     { return "XSS 检测" }
func (m *XSSScanner) Category() string { return "vuln" }

func (m *XSSScanner) Params() []engine.ModuleParam {
	return []engine.ModuleParam{engine.VulnVerificationParam()}
}

func (m *XSSScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	m.base = engine.NewVulnScanner(config, engine.WithTimeout(10*time.Second))
	m.wafEnc = engine.NewWAFBypassEncoder(engine.BuildScanContext(config))
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

	for _, p := range m.getXSSPayloads(canary) {
		value := strings.ReplaceAll(p.Value, "{canary}", canary)
		expect := strings.ReplaceAll(p.Expect, "{canary}", canary)

		body, _, _ := m.base.SendInjected(ctx, target, point, value)
		if body == "" {
			continue
		}

		if strings.Contains(body, expect) {
			return &engine.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "xss_reflected",
				Title:       fmt.Sprintf("反射型XSS - %s: %s", point.Type, point.Name),
				Description: fmt.Sprintf("%s参数 %s 的值被直接反射到响应中且未充分编码 (context: %s)", point.Type, point.Name, p.Context),
				Severity:    "medium",
				Confidence:  80,
				Evidence:    engine.Truncate(extractContext(body, expect, 200), 500),
				Timestamp:   time.Now(),
				Data: map[string]string{
					"param":      point.Name,
					"payload":    value,
					"context":    p.Context,
					"type":       "reflected",
					"inject_via": string(point.Type),
				},
			}
		}
	}

	return nil
}

func (m *XSSScanner) getXSSPayloads(canary string) []payload.XSSPayloadEntry {
	if m.payloads != nil {
		cfg := m.payloads.GetXSS()
		if cfg != nil && len(cfg.Payloads) > 0 {
			return cfg.Payloads
		}
	}
	return defaultXSSPayloads(canary)
}

func (m *XSSScanner) getDOMSinkPatterns() []model.VulnPayloadPattern {
	if m.payloads != nil {
		cfg := m.payloads.GetXSS()
		if cfg != nil && len(cfg.DOMSinks) > 0 {
			return cfg.DOMSinks
		}
	}
	return defaultDOMSinkPatterns()
}

func (m *XSSScanner) getDOMSourcePatterns() []model.VulnPayloadPattern {
	if m.payloads != nil {
		cfg := m.payloads.GetXSS()
		if cfg != nil && len(cfg.DOMSources) > 0 {
			return cfg.DOMSources
		}
	}
	return defaultDOMSourcePatterns()
}

func (m *XSSScanner) testDOMSinks(ctx context.Context, target *engine.Target) []*engine.Finding {
	body := m.base.FetchBody(ctx, target.URL)
	if body == "" {
		return nil
	}

	var findings []*engine.Finding
	foundSinks := map[string]bool{}
	foundSources := map[string]bool{}

	for _, p := range m.getDOMSinkPatterns() {
		re := regexp.MustCompile(p.Pattern)
		if re.MatchString(body) {
			foundSinks[p.Name] = true
		}
	}
	for _, p := range m.getDOMSourcePatterns() {
		re := regexp.MustCompile(p.Pattern)
		if re.MatchString(body) {
			foundSources[p.Name] = true
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

func defaultXSSPayloads(canary string) []payload.XSSPayloadEntry {
	return []payload.XSSPayloadEntry{
		{Value: fmt.Sprintf(`<script>alert('%s')</script>`, canary), Expect: fmt.Sprintf(`<script>alert('%s')</script>`, canary), Context: "html"},
		{Value: fmt.Sprintf(`"><img src=x onerror=alert('%s')>`, canary), Expect: fmt.Sprintf(`onerror=alert('%s')`, canary), Context: "attribute"},
		{Value: fmt.Sprintf(`'><svg/onload=alert('%s')>`, canary), Expect: fmt.Sprintf(`onload=alert('%s')`, canary), Context: "tag-break"},
		{Value: fmt.Sprintf(`javascript:alert('%s')`, canary), Expect: fmt.Sprintf(`javascript:alert('%s')`, canary), Context: "href"},
		{Value: fmt.Sprintf(`" onfocus="alert('%s')" autofocus="`, canary), Expect: fmt.Sprintf(`onfocus="alert('%s')"`, canary), Context: "event-handler"},
		{Value: fmt.Sprintf(`<details open ontoggle=alert('%s')>`, canary), Expect: fmt.Sprintf(`ontoggle=alert('%s')`, canary), Context: "html5-element"},
		{Value: fmt.Sprintf(`<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert('%s') src=1>">`, canary), Expect: fmt.Sprintf(`onerror=alert('%s')`, canary), Context: "mutation-xss"},
		{Value: fmt.Sprintf(`</script><script>alert('%s')</script>`, canary), Expect: fmt.Sprintf(`alert('%s')`, canary), Context: "script-break"},
		{Value: fmt.Sprintf(`'-alert('%s')-'`, canary), Expect: fmt.Sprintf(`alert('%s')`, canary), Context: "js-string"},
		{Value: fmt.Sprintf(`\x3cscript\x3ealert('%s')\x3c/script\x3e`, canary), Expect: fmt.Sprintf(`alert('%s')`, canary), Context: "hex-encode"},
	}
}

func defaultDOMSinkPatterns() []model.VulnPayloadPattern {
	return []model.VulnPayloadPattern{
		{Pattern: `document\.write\s*\(`, Name: "document.write", Category: "dom_sink", Enabled: true},
		{Pattern: `document\.writeln\s*\(`, Name: "document.writeln", Category: "dom_sink", Enabled: true},
		{Pattern: `\.innerHTML\s*=`, Name: "innerHTML", Category: "dom_sink", Enabled: true},
		{Pattern: `\.outerHTML\s*=`, Name: "outerHTML", Category: "dom_sink", Enabled: true},
		{Pattern: `eval\s*\(`, Name: "eval", Category: "dom_sink", Enabled: true},
		{Pattern: `setTimeout\s*\(\s*['"]`, Name: "setTimeout", Category: "dom_sink", Enabled: true},
		{Pattern: `setInterval\s*\(\s*['"]`, Name: "setInterval", Category: "dom_sink", Enabled: true},
		{Pattern: `new\s+Function\s*\(`, Name: "Function constructor", Category: "dom_sink", Enabled: true},
		{Pattern: `\.insertAdjacentHTML\s*\(`, Name: "insertAdjacentHTML", Category: "dom_sink", Enabled: true},
		{Pattern: `window\.location\s*=`, Name: "window.location", Category: "dom_sink", Enabled: true},
		{Pattern: `location\.href\s*=`, Name: "location.href", Category: "dom_sink", Enabled: true},
		{Pattern: `location\.assign\s*\(`, Name: "location.assign", Category: "dom_sink", Enabled: true},
		{Pattern: `location\.replace\s*\(`, Name: "location.replace", Category: "dom_sink", Enabled: true},
	}
}

func defaultDOMSourcePatterns() []model.VulnPayloadPattern {
	return []model.VulnPayloadPattern{
		{Pattern: `location\.hash`, Name: "location.hash", Category: "dom_source", Enabled: true},
		{Pattern: `location\.search`, Name: "location.search", Category: "dom_source", Enabled: true},
		{Pattern: `location\.href`, Name: "location.href", Category: "dom_source", Enabled: true},
		{Pattern: `document\.URL`, Name: "document.URL", Category: "dom_source", Enabled: true},
		{Pattern: `document\.documentURI`, Name: "document.documentURI", Category: "dom_source", Enabled: true},
		{Pattern: `document\.referrer`, Name: "document.referrer", Category: "dom_source", Enabled: true},
		{Pattern: `window\.name`, Name: "window.name", Category: "dom_source", Enabled: true},
		{Pattern: `postMessage`, Name: "postMessage", Category: "dom_source", Enabled: true},
	}
}
