package ssti

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vulnscan-backend/scan/engine"
)

type SSTIScanner struct {
	base *engine.VulnScanner
}

func New() *SSTIScanner {
	return &SSTIScanner{}
}

func (m *SSTIScanner) ID() string       { return "ssti" }
func (m *SSTIScanner) Name() string     { return "模板注入检测" }
func (m *SSTIScanner) Category() string { return "vuln" }

func (m *SSTIScanner) Params() []engine.ModuleParam {
	return []engine.ModuleParam{engine.VulnVerificationParam()}
}

func (m *SSTIScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	m.base = engine.NewVulnScanner(config)
	verifyLevel := engine.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *engine.Target) []*engine.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	engine.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

type sstiProbe struct {
	payload  string
	expect   string
	engine   string
	category string
}

var mathProbes = []sstiProbe{
	{"{{7*7}}", "49", "Jinja2/Twig", "math"},
	{"${7*7}", "49", "Freemarker/Mako", "math"},
	{"<%= 7*7 %>", "49", "ERB/EJS", "math"},
	{"#{7*7}", "49", "Ruby/Pug", "math"},
	{"{{7*'7'}}", "7777777", "Jinja2", "math-str"},
	{"${7*7}", "49", "Velocity/Thymeleaf", "math"},
	{"[#assign x=7*7]${x}", "49", "Freemarker-assign", "math"},
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

var exploitProbes = []sstiExploit{
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

func (m *SSTIScanner) testTarget(ctx context.Context, target *engine.Target, verifyLevel string) []*engine.Finding {
	points := engine.ExtractInjectionPoints(target)
	if len(points) == 0 {
		parsed, err := url.Parse(target.URL)
		if err != nil || len(parsed.Query()) == 0 {
			return nil
		}
		for param := range parsed.Query() {
			points = append(points, engine.InjectionPoint{
				Type: engine.InjectQuery,
				Name: param,
			})
		}
	}

	if len(points) == 0 {
		return nil
	}

	var findings []*engine.Finding
	baseBody := m.base.FetchBody(ctx, target.URL)

	for _, point := range points {
		if engine.ShouldRunPrinciple(verifyLevel) {
			if f := m.testMathExpression(ctx, target, point, baseBody); f != nil {
				findings = append(findings, f)
				continue
			}
			if f := m.testErrorBased(ctx, target, point); f != nil {
				findings = append(findings, f)
				continue
			}
		}

		if engine.ShouldRunExploit(verifyLevel) {
			if f := m.testExploit(ctx, target, point, baseBody); f != nil {
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (m *SSTIScanner) testMathExpression(ctx context.Context, target *engine.Target, point engine.InjectionPoint, baseBody string) *engine.Finding {
	for _, probe := range mathProbes {
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
			return &engine.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "ssti",
				Title:              fmt.Sprintf("SSTI 模板注入(%s) - %s: %s", probe.engine, point.Type, point.Name),
				Description:        fmt.Sprintf("%s参数 %s 注入 %s 后响应包含预期计算结果 %s，疑似 %s 引擎", point.Type, point.Name, probe.payload, probe.expect, probe.engine),
				Severity:           "high",
				Confidence:         80,
				Evidence:           engine.Truncate(body, 500),
				VerificationLevel:  engine.VerifyPrinciple,
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

func (m *SSTIScanner) testErrorBased(ctx context.Context, target *engine.Target, point engine.InjectionPoint) *engine.Finding {
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
				return &engine.Finding{
					ModuleID:           m.ID(),
					Target:             target,
					Type:               "ssti_error",
					Title:              fmt.Sprintf("SSTI 模板引擎错误泄露 - %s: %s", point.Type, point.Name),
					Description:        fmt.Sprintf("%s参数 %s 注入 %s 后触发模板引擎错误", point.Type, point.Name, payload),
					Severity:           "medium",
					Confidence:         70,
					Evidence:           engine.Truncate(body, 500),
					VerificationLevel:  engine.VerifyPrinciple,
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

func (m *SSTIScanner) testExploit(ctx context.Context, target *engine.Target, point engine.InjectionPoint, baseBody string) *engine.Finding {
	for _, probe := range exploitProbes {
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
			return &engine.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "ssti_exploit",
				Title:              fmt.Sprintf("SSTI 实际利用(%s) - %s: %s", probe.engine, point.Type, point.Name),
				Description:        fmt.Sprintf("%s参数 %s 通过 %s 引擎成功提取敏感信息", point.Type, point.Name, probe.engine),
				Severity:           "critical",
				Confidence:         90,
				Evidence:           engine.Truncate(body, 500),
				VerificationLevel:  engine.VerifyExploit,
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
