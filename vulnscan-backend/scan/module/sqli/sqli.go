package sqli

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/vulnkit"
)

type SQLiScanner struct {
	base     *vulnkit.VulnScanner
	scanCtx  *vulnkit.ScanContext
	wafEnc   *vulnkit.WAFBypassEncoder
	payloads *payload.Loader
}

func New(loader *payload.Loader) *SQLiScanner {
	return &SQLiScanner{payloads: loader}
}

func (m *SQLiScanner) ID() string       { return "sqli" }
func (m *SQLiScanner) Name() string     { return "SQL 注入检测" }
func (m *SQLiScanner) Category() string { return "vuln" }

func (m *SQLiScanner) Params() []core.ModuleParam {
	return []core.ModuleParam{core.VulnVerificationParam()}
}

func (m *SQLiScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	m.base = vulnkit.NewVulnScanner(config)
	m.scanCtx = vulnkit.BuildScanContext(config)
	m.wafEnc = vulnkit.NewWAFBypassEncoder(m.scanCtx)
	verifyLevel := core.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *core.Target) []*core.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	vulnkit.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *SQLiScanner) testTarget(ctx context.Context, target *core.Target, verifyLevel string) []*core.Finding {
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

	if len(points) == 0 {
		return nil
	}

	baseBody := m.base.FetchBody(ctx, target.URL)
	var findings []*core.Finding

	for _, point := range points {
		found := false

		if core.ShouldRunPrinciple(verifyLevel) {
			if f := m.testErrorBased(ctx, target, point); f != nil {
				f.VerificationLevel = core.VerifyPrinciple
				f.VerificationDetail = "error-pattern-match"
				findings = append(findings, f)
				found = true
			}
			if !found {
				if f := m.testUnionBased(ctx, target, point); f != nil {
					f.VerificationLevel = core.VerifyPrinciple
					f.VerificationDetail = "union-column-probe"
					findings = append(findings, f)
					found = true
				}
			}
		}

		if core.ShouldRunExploit(verifyLevel) {
			if f := m.testBooleanBased(ctx, target, point, baseBody); f != nil {
				f.VerificationLevel = core.VerifyExploit
				f.VerificationDetail = "boolean-response-diff"
				findings = append(findings, f)
				found = true
			}
			if !found {
				if f := m.testTimeBased(ctx, target, point); f != nil {
					f.VerificationLevel = core.VerifyExploit
					f.VerificationDetail = "time-delay-confirmed"
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

func (m *SQLiScanner) testErrorBased(ctx context.Context, target *core.Target, point vulnkit.InjectionPoint) *core.Finding {
	payloads := m.getErrorPayloads()

	for _, p := range payloads {
		body, _, err := m.base.SendInjected(ctx, target, point, p)
		if err != nil || body == "" {
			continue
		}

		for _, pattern := range m.getErrorPatterns() {
			if pattern.MatchString(body) {
				return &core.Finding{
					ModuleID:    m.ID(),
					Target:      target,
					Type:        "sqli_error",
					Title:       fmt.Sprintf("SQL注入(Error-based) - %s: %s", point.Type, point.Name),
					Description: fmt.Sprintf("%s参数 %s 使用 payload '%s' 触发了数据库错误", point.Type, point.Name, p),
					Severity:    "high",
					Confidence:  85,
					Evidence:    vulnkit.Truncate(body, 500),
					Timestamp:   time.Now(),
					Data: map[string]string{
						"param":      point.Name,
						"payload":    p,
						"type":       "error-based",
						"inject_via": string(point.Type),
					},
				}
			}
		}
	}

	return nil
}

func (m *SQLiScanner) testBooleanBased(ctx context.Context, target *core.Target, point vulnkit.InjectionPoint, baseBody string) *core.Finding {
	boolPairs := m.getBooleanPairs()

	for _, pair := range boolPairs {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		trueBody, _, _ := m.base.SendInjected(ctx, target, point, pair.TruePayload)
		falseBody, _, _ := m.base.SendInjected(ctx, target, point, pair.FalsePayload)

		if trueBody == "" || falseBody == "" {
			continue
		}

		trueDiff := levenshteinRatio(baseBody, trueBody)
		falseDiff := levenshteinRatio(baseBody, falseBody)
		tfDiff := levenshteinRatio(trueBody, falseBody)

		if trueDiff > 0.75 && falseDiff < 0.5 && tfDiff < 0.6 {
			return &core.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "sqli_boolean",
				Title:       fmt.Sprintf("SQL注入(Boolean-based) - %s: %s", point.Type, point.Name),
				Description: fmt.Sprintf("%s参数 %s 检测，true/false 响应差异显著 (true=%.2f, false=%.2f, tf_diff=%.2f)", point.Type, point.Name, trueDiff, falseDiff, tfDiff),
				Severity:    "high",
				Confidence:  75,
				Timestamp:   time.Now(),
				Data: map[string]string{
					"param":         point.Name,
					"type":          "boolean-based",
					"true_payload":  pair.TruePayload,
					"false_payload": pair.FalsePayload,
					"true_ratio":    fmt.Sprintf("%.2f", trueDiff),
					"false_ratio":   fmt.Sprintf("%.2f", falseDiff),
					"inject_via":    string(point.Type),
				},
			}
		}
	}

	return nil
}

func (m *SQLiScanner) testTimeBased(ctx context.Context, target *core.Target, point vulnkit.InjectionPoint) *core.Finding {
	timePayloads := m.getTimePayloads()

	baseStart := time.Now()
	m.base.FetchBody(ctx, target.URL)
	baselineLatency := time.Since(baseStart)
	threshold := baselineLatency + 4*time.Second

	for _, tp := range timePayloads {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		start := time.Now()
		m.base.SendInjected(ctx, target, point, tp.Value)
		elapsed := time.Since(start)

		if elapsed >= threshold && elapsed >= 4500*time.Millisecond {
			confirmStart := time.Now()
			m.base.SendInjected(ctx, target, point, tp.Value)
			confirmElapsed := time.Since(confirmStart)

			if confirmElapsed >= threshold && confirmElapsed >= 4*time.Second {
				confidence := 80
				if confirmElapsed >= 5*time.Second {
					confidence = 90
				}

				dbType := "unknown"
				if len(tp.Databases) > 0 {
					dbType = tp.Databases[0]
				}

				return &core.Finding{
					ModuleID:    m.ID(),
					Target:      target,
					Type:        "sqli_time",
					Title:       fmt.Sprintf("SQL注入(Time-based) - %s: %s [%s]", point.Type, point.Name, dbType),
					Description: fmt.Sprintf("%s参数 %s 使用 %s payload 触发延迟 (第1次: %v, 第2次: %v, 基线: %v)", point.Type, point.Name, dbType, elapsed.Round(time.Millisecond), confirmElapsed.Round(time.Millisecond), baselineLatency.Round(time.Millisecond)),
					Severity:    "high",
					Confidence:  confidence,
					Timestamp:   time.Now(),
					Data: map[string]string{
						"param":      point.Name,
						"payload":    tp.Value,
						"db_type":    dbType,
						"type":       "time-based",
						"delay_1":    elapsed.String(),
						"delay_2":    confirmElapsed.String(),
						"baseline":   baselineLatency.String(),
						"inject_via": string(point.Type),
					},
				}
			}
		}
	}

	return nil
}

func (m *SQLiScanner) testUnionBased(ctx context.Context, target *core.Target, point vulnkit.InjectionPoint) *core.Finding {
	for cols := 1; cols <= 10; cols++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		nulls := make([]string, cols)
		for i := range nulls {
			nulls[i] = "NULL"
		}
		payload := fmt.Sprintf("' UNION SELECT %s-- ", strings.Join(nulls, ","))
		body, _, err := m.base.SendInjected(ctx, target, point, payload)
		if err != nil || body == "" {
			continue
		}

		hasError := false
		for _, pattern := range m.getErrorPatterns() {
			if pattern.MatchString(body) {
				hasError = true
				break
			}
		}

		if !hasError && cols > 1 {
			return &core.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "sqli_union",
				Title:       fmt.Sprintf("SQL注入(UNION-based) - %s: %s (%d列)", point.Type, point.Name, cols),
				Description: fmt.Sprintf("%s参数 %s 使用 UNION SELECT %d 列成功注入，无错误回显", point.Type, point.Name, cols),
				Severity:    "critical",
				Confidence:  85,
				Timestamp:   time.Now(),
				Data: map[string]string{
					"param":      point.Name,
					"payload":    payload,
					"type":       "union-based",
					"columns":    fmt.Sprintf("%d", cols),
					"inject_via": string(point.Type),
				},
			}
		}
	}
	return nil
}

func (m *SQLiScanner) getErrorPayloads() []string {
	db := m.scanCtx.DetectedDBType()
	var values []string

	if m.payloads != nil {
		cfg := m.payloads.GetSQLi()
		if cfg != nil {
			for _, p := range cfg.ErrorPayloads {
				if db == "" {
					values = append(values, p.Value)
				} else {
					for _, d := range p.Databases {
						if d == "all" || strings.EqualFold(d, db) {
							values = append(values, p.Value)
							break
						}
					}
				}
			}
		}
	}

	if len(values) == 0 {
		payload.LogFallbackOnce("sqli")
		values = payload.MinimalSQLiErrorPayloads(db)
	}

	if m.wafEnc.HasWAF() {
		values = m.wafEnc.EncodePayloads(values)
	}
	return values
}

func (m *SQLiScanner) getTimePayloads() []payload.PayloadEntry {
	db := m.scanCtx.DetectedDBType()
	var result []payload.PayloadEntry

	if m.payloads != nil {
		cfg := m.payloads.GetSQLi()
		if cfg != nil {
			for _, p := range cfg.TimePayloads {
				if db == "" {
					result = append(result, p)
				} else {
					for _, d := range p.Databases {
						if d == "all" || strings.EqualFold(d, db) {
							result = append(result, p)
							break
						}
					}
				}
			}
		}
	}

	if len(result) == 0 {
		payload.LogFallbackOnce("sqli")
		for _, p := range payload.MinimalSQLiTimePayloads() {
			result = append(result, payload.PayloadEntry{Value: p.Value, Databases: []string{p.Type}})
		}
	}

	return result
}

func (m *SQLiScanner) getBooleanPairs() []payload.BooleanPair {
	if m.payloads != nil {
		cfg := m.payloads.GetSQLi()
		if cfg != nil && len(cfg.BooleanPairs) > 0 {
			return cfg.BooleanPairs
		}
	}
	payload.LogFallbackOnce("sqli")
	return payload.MinimalSQLiBooleanPairs()
}

func (m *SQLiScanner) getErrorPatterns() []*regexp.Regexp {
	var patterns []*regexp.Regexp

	if m.payloads != nil {
		cfg := m.payloads.GetSQLi()
		if cfg != nil {
			for _, p := range cfg.ErrorPatterns {
				patterns = append(patterns, regexp.MustCompile(p.Pattern))
			}
		}
	}

	if len(patterns) == 0 {
		payload.LogFallbackOnce("sqli")
		patterns = payload.CompilePatterns(payload.MinimalSQLiErrorPatterns())
	}

	return patterns
}

func levenshteinRatio(a, b string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}

	la := min(len(a), 2000)
	lb := min(len(b), 2000)
	a = a[:la]
	b = b[:lb]

	common := 0
	setA := make(map[string]int)
	for _, line := range strings.Split(a, "\n") {
		setA[strings.TrimSpace(line)]++
	}
	for _, line := range strings.Split(b, "\n") {
		key := strings.TrimSpace(line)
		if setA[key] > 0 {
			common++
			setA[key]--
		}
	}

	total := len(strings.Split(a, "\n")) + len(strings.Split(b, "\n"))
	if total == 0 {
		return 1.0
	}
	return float64(2*common) / float64(total)
}
