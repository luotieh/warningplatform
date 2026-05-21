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
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/scanhttp"
	"vulnscan-backend/scan/vulnkit"
)

type XSSScanner struct {
	base     *vulnkit.VulnScanner
	scanCtx  *vulnkit.ScanContext
	wafEnc   *vulnkit.WAFBypassEncoder
	payloads *payload.Loader
}

func New(loader *payload.Loader) *XSSScanner {
	return &XSSScanner{payloads: loader}
}

func (m *XSSScanner) ID() string       { return "xss" }
func (m *XSSScanner) Name() string     { return "XSS 检测" }
func (m *XSSScanner) Category() string { return "vuln" }

func (m *XSSScanner) Params() []core.ModuleParam {
	return []core.ModuleParam{core.VulnVerificationParam()}
}

func (m *XSSScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	m.base = vulnkit.NewVulnScanner(config, scanhttp.WithTimeout(10*time.Second))
	m.wafEnc = vulnkit.NewWAFBypassEncoder(vulnkit.BuildScanContext(config))
	verifyLevel := core.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *core.Target) []*core.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	vulnkit.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *XSSScanner) testTarget(ctx context.Context, target *core.Target, verifyLevel string) []*core.Finding {
	points := vulnkit.ExtractInjectionPoints(target)
	if len(points) == 0 {
		parsedURL, err := url.Parse(target.URL)
		if err != nil || len(parsedURL.Query()) == 0 {
			return nil
		}
		for param := range parsedURL.Query() {
			points = append(points, vulnkit.InjectionPoint{
				Type: vulnkit.InjectQuery,
				Name: param,
			})
		}
	}

	var findings []*core.Finding

	if core.ShouldRunPrinciple(verifyLevel) {
		for _, point := range points {
			if f := m.testReflected(ctx, target, point); f != nil {
				f.VerificationLevel = core.VerifyPrinciple
				f.VerificationDetail = "payload-reflected"
				findings = append(findings, f)
			}
		}

		if f := m.testDOMSinks(ctx, target); f != nil {
			for _, finding := range f {
				finding.VerificationLevel = core.VerifyPrinciple
				finding.VerificationDetail = "dom-sink-detected"
			}
			findings = append(findings, f...)
		}
	}

	return findings
}

func (m *XSSScanner) testReflected(ctx context.Context, target *core.Target, point vulnkit.InjectionPoint) *core.Finding {
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
			return &core.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "xss_reflected",
				Title:       fmt.Sprintf("反射型XSS - %s: %s", point.Type, point.Name),
				Description: fmt.Sprintf("%s参数 %s 的值被直接反射到响应中且未充分编码 (context: %s)", point.Type, point.Name, p.Context),
				Severity:    "medium",
				Confidence:  80,
				Evidence:    vulnkit.Truncate(extractContext(body, expect, 200), 500),
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
	payload.LogFallbackOnce("xss")
	return payload.MinimalXSSPayloads(canary)
}

func (m *XSSScanner) getDOMSinkPatterns() []model.VulnPayloadPattern {
	if m.payloads != nil {
		cfg := m.payloads.GetXSS()
		if cfg != nil && len(cfg.DOMSinks) > 0 {
			return cfg.DOMSinks
		}
	}
	payload.LogFallbackOnce("xss")
	return payload.MinimalDOMSinkPatterns()
}

func (m *XSSScanner) getDOMSourcePatterns() []model.VulnPayloadPattern {
	if m.payloads != nil {
		cfg := m.payloads.GetXSS()
		if cfg != nil && len(cfg.DOMSources) > 0 {
			return cfg.DOMSources
		}
	}
	payload.LogFallbackOnce("xss")
	return payload.MinimalDOMSourcePatterns()
}

func (m *XSSScanner) testDOMSinks(ctx context.Context, target *core.Target) []*core.Finding {
	body := m.base.FetchBody(ctx, target.URL)
	if body == "" {
		return nil
	}

	var findings []*core.Finding
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

		findings = append(findings, &core.Finding{
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
