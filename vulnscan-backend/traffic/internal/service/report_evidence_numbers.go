package service

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var reportNumericTokens = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)*`)
var reportChineseCounts = regexp.MustCompile(`([零〇一二三四五六七八九十百千万亿两]+)\s*(次|条|个|包|字节|秒|分钟|小时|天|%|％)`)
var reportSourceTimestamps = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)

// Check numbers against the cited evidence's actual scope. Longest tokens keep
// an address or decimal indivisible; another row's numbers cannot authorize it.
func validateReportNumbers(text string, refs []string, entries map[string]ReportEvidence) error {
	allowed := map[string]bool{}
	for _, id := range refs {
		e := entries[id]
		source := e.Result
		if len(e.Measurements) > 0 {
			raw, _ := json.Marshal(e.Measurements)
			source += " " + string(raw)
		}
		// Only endpoint addresses/ports are facts; opaque asset/device IDs are not.
		if endpoint, err := url.Parse(e.Scope.EndpointID); err == nil && endpoint.Host != "" {
			source += " " + endpoint.Hostname() + " " + endpoint.Port()
		}
		if e.Window != nil {
			for _, at := range []time.Time{e.Window.Start, e.Window.End} {
				if !at.IsZero() {
					source += " " + at.Format(time.RFC3339Nano)
				}
			}
		}
		if e.Finding != nil {
			raw, _ := json.Marshal(e.Finding.Measurements)
			source += " " + string(raw)
		}
		// Prose commonly omits subsecond precision. Normalize only parsed source
		// timestamps, never truncate arbitrary measurements to authorize a count.
		for _, stamp := range reportSourceTimestamps.FindAllString(source, -1) {
			if at, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
				source += " " + at.Truncate(time.Second).Format(time.RFC3339)
				source += " " + at.In(time.FixedZone("Asia/Shanghai", 8*60*60)).Truncate(time.Second).Format(time.RFC3339)
			}
		}
		source = normalizeReportChineseCounts(source)
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
	text = normalizeReportChineseCounts(text)
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

// Normalize a quantity in both cited material and prose. This never creates an
// allowed number independently of the cited row (e.g. 五分钟桶 remains 5分钟桶).
func normalizeReportChineseCounts(text string) string {
	return reportChineseCounts.ReplaceAllStringFunc(text, func(term string) string {
		parts := reportChineseCounts.FindStringSubmatch(term)
		n, ok := reportChineseInteger(parts[1])
		if !ok {
			return term
		}
		// Keep a preceding timestamp/count separate: 12:30五分钟 must not
		// become the invented numeric token 305.
		return " " + strconv.FormatInt(n, 10) + parts[2]
	})
}

func reportChineseInteger(text string) (int64, bool) {
	digits := map[rune]int64{'零': 0, '〇': 0, '一': 1, '二': 2, '两': 2, '三': 3, '四': 4, '五': 5, '六': 6, '七': 7, '八': 8, '九': 9}
	units := map[rune]int64{'十': 10, '百': 100, '千': 1000, '万': 10000, '亿': 100000000}
	const limit int64 = 1000000000000
	if !strings.ContainsAny(text, "十百千万亿") {
		var n int64
		for _, r := range text {
			d, ok := digits[r]
			if !ok || n > (limit-d)/10 {
				return 0, false
			}
			n = n*10 + d
		}
		return n, text != ""
	}
	var total, section, digit int64
	lastSmallUnit := int64(10000)
	for _, r := range text {
		if d, ok := digits[r]; ok {
			if digit != 0 {
				return 0, false
			}
			digit = d
			continue
		}
		u, ok := units[r]
		if !ok {
			return 0, false
		}
		if u < 10000 {
			if u >= lastSmallUnit {
				return 0, false
			}
			lastSmallUnit = u
			if digit == 0 {
				digit = 1
			}
			section += digit * u
		} else {
			section += digit
			if u == 100000000 {
				if total+section > limit/u {
					return 0, false
				}
				total = (total + section) * u
			} else {
				if section > limit/u || total > limit-section*u {
					return 0, false
				}
				total += section * u
			}
			section = 0
			lastSmallUnit = 10000
		}
		digit = 0
		if total+section > limit {
			return 0, false
		}
	}
	return total + section + digit, total+section+digit <= limit
}
