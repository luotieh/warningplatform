package service

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var reportNumericTokens = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)*`)
var reportChineseCounts = regexp.MustCompile(`[零〇一二三四五六七八九十百千万亿两]+\s*(次|条|个|包|字节|秒|分钟|小时|天|%|％)`)
var reportSourceTimestamps = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)

// Check numbers against the cited evidence's actual scope. Longest tokens keep
// an address or decimal indivisible; another row's numbers cannot authorize it.
func validateReportNumbers(text string, refs []string, entries map[string]ReportEvidence) error {
	allowed := map[string]bool{}
	for _, id := range refs {
		e := entries[id]
		source := e.Result
		if e.Finding != nil {
			raw, _ := json.Marshal(e.Finding.Measurements)
			source += " " + string(raw)
		}
		// Prose commonly omits subsecond precision. Normalize only parsed source
		// timestamps, never truncate arbitrary measurements to authorize a count.
		for _, stamp := range reportSourceTimestamps.FindAllString(source, -1) {
			if at, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
				source += " " + at.Truncate(time.Second).Format(time.RFC3339)
			}
		}
		for _, n := range reportNumericTokens.FindAllString(source, -1) {
			allowed[n] = true
			if strings.Count(n, ".") == 1 {
				if v, err := strconv.ParseFloat(n, 64); err == nil {
					for precision := 0; precision <= 6; precision++ {
						allowed[strconv.FormatFloat(v, 'f', precision, 64)] = true
					}
				}
			}
		}
	}
	for _, term := range []string{"C2", "JA3", "JA4", "HTTP/1.1", "HTTP/2"} {
		text = strings.ReplaceAll(text, term, "")
	}
	for id := range entries {
		text = strings.ReplaceAll(text, id, "")
	}
	for _, n := range reportNumericTokens.FindAllString(text, -1) {
		if !allowed[n] {
			return fmt.Errorf("report_fact_numbers_not_in_cited_scope: value=%s refs=%s", n, strings.Join(refs, ","))
		}
	}
	if reportChineseCounts.MatchString(text) {
		return fmt.Errorf("report_count_requires_numeric_citation")
	}
	return nil
}
