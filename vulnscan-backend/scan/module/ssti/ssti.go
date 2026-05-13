package ssti

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/vulnkit"
)

type SSTIScanner struct {
	base     *vulnkit.VulnScanner
	payloads *payload.Loader
}

func New(loader *payload.Loader) *SSTIScanner {
	return &SSTIScanner{payloads: loader}
}

func (m *SSTIScanner) ID() string       { return "ssti" }
func (m *SSTIScanner) Name() string     { return "模板注入检测" }
func (m *SSTIScanner) Category() string { return "vuln" }

func (m *SSTIScanner) Params() []core.ModuleParam {
	return []core.ModuleParam{core.VulnVerificationParam()}
}

type sstiProbe struct {
	payload  string
	expect   string
	engine   string
	category string
}

func (m *SSTIScanner) getMathProbes() []sstiProbe {
	if m.payloads != nil {
		dbPayloads := m.payloads.GetPayloads("ssti")
		var result []sstiProbe
		for _, p := range dbPayloads {
			if p.Type == "basic" || p.Type == "math" {
				expect := p.Expect
				if expect == "" {
					if strings.Contains(p.Value, "7*7") || strings.Contains(p.Value, "7*'7'") {
						if strings.Contains(p.Value, "{{") {
							if strings.Contains(p.Value, "7*'7'") {
								expect = "7777777"
							} else {
								expect = "49"
							}
						} else if strings.Contains(p.Value, "${") {
							expect = "49"
						}
					}
				}
				if expect != "" {
					engine := p.Tags
					if engine == "" {
						engine = "Template"
					}
					result = append(result, sstiProbe{
						payload:  p.Value,
						expect:   expect,
						engine:   engine,
						category: "math",
					})
				}
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultMathProbes()
}

func defaultMathProbes() []sstiProbe {
	return []sstiProbe{
		{"{{7*7}}", "49", "Jinja2/Twig", "math"},
		{"${7*7}", "49", "Freemarker/Mako", "math"},
		{"<%= 7*7 %>", "49", "ERB/EJS", "math"},
		{"#{7*7}", "49", "Ruby/Pug", "math"},
		{"{{7*'7'}}", "7777777", "Jinja2", "math-str"},
		{"${7*7}", "49", "Velocity/Thymeleaf", "math"},
		{"[#assign x=7*7]${x}", "49", "Freemarker-assign", "math"},
	}
}

var engineErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)jinja2\.exceptions`),
	regexp.MustCompile(`(?i)twig.*error`),
	regexp.MustCompile(`(?i)freemarker\.template`),
	regexp.MustCompile(`(?i)velocity.*error`),
	regexp.MustCompile(`(?i)thymeleaf.*error`),
	regexp.MustCompile(`(?i)pebble.*error`),
	regexp.MustCompile(`(?i)mako\.exceptions`),
	regexp.MustCompile(`(?i)smarty.*error`),
	regexp.MustCompile(`(?i)TemplateDoesNotExist`),
	regexp.MustCompile(`(?i)UndefinedError`),
}

type sstiExploit struct {
	payload string
	detect  func(body string) bool
	engine  string
	detail  string
}

func (m *SSTIScanner) getExploitProbes() []sstiExploit {
	if m.payloads != nil {
		dbPayloads := m.payloads.GetPayloads("ssti")
		var result []sstiExploit
		for _, p := range dbPayloads {
			if p.Type == "config_leak" || p.Type == "rce" {
				engine := p.Tags
				if engine == "" {
					engine = "Template"
				}
				value := p.Value
				detect := func(body string) bool {
					if strings.Contains(value, "config") {
						return strings.Contains(body, "SECRET_KEY") || strings.Contains(body, "DEBUG")
					}
					if strings.Contains(value, "version") {
						return regexp.MustCompile(`\d+\.\d+\.\d+`).MatchString(body)
					}
					return strings.Contains(body, p.Expect)
				}
				result = append(result, sstiExploit{
					payload: value,
					detect:  detect,
					engine:  engine,
					detail:  p.Name,
				})
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultExploitProbes()
}

func defaultExploitProbes() []sstiExploit {
	return []sstiExploit{
		{
			payload: "{{config}}",
			detect:  func(body string) bool { return strings.Contains(body, "SECRET_KEY") || strings.Contains(body, "DEBUG") },
			engine:  "Jinja2/Flask",
			detail:  "config-object-leaked",
		},
		{
			payload: "{{self.__class__.__mro__}}",
			detect:  func(body string) bool { return strings.Contains(body, "object") && strings.Contains(body, "class") },
			engine:  "Jinja2",
			detail:  "mro-chain-exposed",
		},
		{
			payload: "${.version}",
			detect:  func(body string) bool { return regexp.MustCompile(`\d+\.\d+\.\d+`).MatchString(body) },
			engine:  "Freemarker",
			detail:  "version-leaked",
		},
		{
			payload: "{{_self.env.getExtension('Twig\\Extension\\CoreExtension')}}",
			detect:  func(body string) bool { return strings.Contains(body, "Twig") },
			engine:  "Twig",
			detail:  "extension-info-leaked",
		},
		{
			payload: "{{range.constructor('return global.process.version')()}}",
			detect: func(body string) bool {
				return regexp.MustCompile(`v\d+\.\d+\.\d+`).MatchString(body)
			},
			engine: "Nunjucks/Pug",
			detail: "node-version-leaked",
		},
	}
}

func (m *SSTIScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	m.base = vulnkit.NewVulnScanner(config)
	verifyLevel := core.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *core.Target) []*core.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	vulnkit.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *SSTIScanner) testTarget(ctx context.Context, target *core.Target, verifyLevel string) []*core.Finding {
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
		if core.ShouldRunPrinciple(verifyLevel) {
			if f := m.testMathExpression(ctx, target, point, baseBody); f != nil {
				findings = append(findings, f)
				continue
			}
			if f := m.testErrorBased(ctx, target, point); f != nil {
				findings = append(findings, f)
				continue
			}
		}

		if core.ShouldRunExploit(verifyLevel) {
			if f := m.testExploit(ctx, target, point, baseBody); f != nil {
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (m *SSTIScanner) testMathExpression(ctx context.Context, target *core.Target, point vulnkit.InjectionPoint, baseBody string) *core.Finding {
	for _, probe := range m.getMathProbes() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		body, _, _ := m.base.SendInjected(ctx, target, point, probe.payload)
		if body == "" {
			continue
		}

		if strings.Contains(body, probe.expect) && !strings.Contains(baseBody, probe.expect) {
			return &core.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "ssti",
				Title:              fmt.Sprintf("SSTI 模板注入(%s) - %s: %s", probe.engine, point.Type, point.Name),
				Description:        fmt.Sprintf("%s参数 %s 注入 %s 后响应包含预期计算结果 %s，疑似 %s 引擎", point.Type, point.Name, probe.payload, probe.expect, probe.engine),
				Severity:           "high",
				Confidence:         80,
				Evidence:           vulnkit.Truncate(body, 500),
				VerificationLevel:  core.VerifyPrinciple,
				VerificationDetail: "math-expression-reflected",
				Timestamp:          time.Now(),
				Data: map[string]string{
					"param":      point.Name,
					"payload":    probe.payload,
					"expect":     probe.expect,
					"engine":     probe.engine,
					"type":       "ssti-math",
					"inject_via": string(point.Type),
				},
			}
		}
	}
	return nil
}

func (m *SSTIScanner) testErrorBased(ctx context.Context, target *core.Target, point vulnkit.InjectionPoint) *core.Finding {
	errorPayloads := []string{"{{", "${", "<%", "#{", "{%"}

	for _, payload := range errorPayloads {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		body, _, _ := m.base.SendInjected(ctx, target, point, payload)
		if body == "" {
			continue
		}

		for _, pattern := range engineErrorPatterns {
			if pattern.MatchString(body) {
				return &core.Finding{
					ModuleID:           m.ID(),
					Target:             target,
					Type:               "ssti_error",
					Title:              fmt.Sprintf("SSTI 模板引擎错误泄露 - %s: %s", point.Type, point.Name),
					Description:        fmt.Sprintf("%s参数 %s 注入 %s 后触发模板引擎错误", point.Type, point.Name, payload),
					Severity:           "medium",
					Confidence:         70,
					Evidence:           vulnkit.Truncate(body, 500),
					VerificationLevel:  core.VerifyPrinciple,
					VerificationDetail: "engine-error-detected",
					Timestamp:          time.Now(),
					Data: map[string]string{
						"param":      point.Name,
						"payload":    payload,
						"pattern":    pattern.String(),
						"type":       "ssti-error",
						"inject_via": string(point.Type),
					},
				}
			}
		}
	}
	return nil
}

func (m *SSTIScanner) testExploit(ctx context.Context, target *core.Target, point vulnkit.InjectionPoint, baseBody string) *core.Finding {
	for _, probe := range m.getExploitProbes() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		body, _, _ := m.base.SendInjected(ctx, target, point, probe.payload)
		if body == "" {
			continue
		}

		if probe.detect(body) && !probe.detect(baseBody) {
			return &core.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "ssti_exploit",
				Title:              fmt.Sprintf("SSTI 实际利用(%s) - %s: %s", probe.engine, point.Type, point.Name),
				Description:        fmt.Sprintf("%s参数 %s 通过 %s 引擎成功提取敏感信息", point.Type, point.Name, probe.engine),
				Severity:           "critical",
				Confidence:         90,
				Evidence:           vulnkit.Truncate(body, 500),
				VerificationLevel:  core.VerifyExploit,
				VerificationDetail: probe.detail,
				Timestamp:          time.Now(),
				Data: map[string]string{
					"param":      point.Name,
					"payload":    probe.payload,
					"engine":     probe.engine,
					"type":       "ssti-exploit",
					"inject_via": string(point.Type),
				},
			}
		}
	}
	return nil
}

var _ = model.VulnPayload{}
