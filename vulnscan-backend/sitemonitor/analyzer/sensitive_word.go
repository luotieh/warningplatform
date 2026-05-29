package analyzer

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
)

type SensitiveWordAnalyzer struct {
	rules RuleAccessor
}

func NewSensitiveWordAnalyzer(rules RuleAccessor) *SensitiveWordAnalyzer {
	return &SensitiveWordAnalyzer{rules: rules}
}

func (a *SensitiveWordAnalyzer) Dimension() string { return "sensitive_word" }

func (a *SensitiveWordAnalyzer) Analyze(ctx context.Context, input *Input) (*Output, error) {
	snap, err := parseSnapshot(input.SnapshotJSON)
	if err != nil {
		return nil, err
	}

	output := &Output{HasIssue: false}
	if snap.Error != "" {
		return output, nil
	}

	words := a.loadSensitiveWords()
	searchText := combineSearchText(snap)
	fullText := searchText + " " + snap.Title
	lowerFull := strings.ToLower(fullText)

	seen := make(map[string]bool, len(words))
	matches := make([]map[string]any, 0)
	totalMatches := 0

	for _, word := range words {
		lw := strings.ToLower(word.Word)
		if seen[lw] {
			continue
		}
		seen[lw] = true

		count := strings.Count(lowerFull, lw)
		if count == 0 {
			continue
		}

		ctx, ctxList, evidenceHTML := extractSensitiveWordEvidence(searchText, word.Word, word.Severity)
		matches = append(matches, map[string]any{
			"word":          word.Word,
			"category":      word.Category,
			"severity":      word.Severity,
			"count":         count,
			"context":       ctx,
			"contexts":      ctxList,
			"evidence_html": evidenceHTML,
		})
		totalMatches += count
	}

	piiMatches := detectPIIPatterns(searchText)
	matches = append(matches, piiMatches...)
	for _, pm := range piiMatches {
		if c, ok := pm["count"].(int); ok {
			totalMatches += c
		}
	}

	if len(matches) > 0 {
		output.HasIssue = true
		highSevCount := 0
		for _, m := range matches {
			if sev, _ := m["severity"].(string); sev == "high" || sev == "critical" {
				highSevCount++
			}
		}
		switch {
		case highSevCount > 0 || totalMatches > 10:
			output.Severity = "high"
		case totalMatches > 3:
			output.Severity = "medium"
		default:
			output.Severity = "low"
		}

		textLen := len([]rune(searchText))
		hits := make([]wordHit, 0, len(matches))
		for _, m := range matches {
			w, _ := m["word"].(string)
			sev, _ := m["severity"].(string)
			if strings.TrimSpace(w) != "" {
				hits = append(hits, wordHit{word: w, severity: sev})
			}
		}
		pageEvidenceHTML := buildPageEvidenceHTML(searchText, hits)
		detailJSON, _ := json.Marshal(map[string]any{
			"matches":            matches,
			"total_matches":      totalMatches,
			"text_length":        textLen,
			"url":                snap.URL,
			"page_evidence_html": pageEvidenceHTML,
		})
		output.DetailsJSON = string(detailJSON)
	}

	return output, nil
}

var piiPatterns = []struct {
	name     string
	category string
	severity string
	re       *regexp.Regexp
	validate func(string) bool
}{
	{
		name:     "中国大陆手机号",
		category: "数据泄露",
		severity: "high",
		re:       regexp.MustCompile(`(?:^|[^\d])1[3-9]\d{9}(?:[^\d]|$)`),
	},
	{
		name:     "身份证号",
		category: "数据泄露",
		severity: "critical",
		re:       regexp.MustCompile(`(?:^|[^\d])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?:[^\d]|$)`),
		validate: validateIDCard,
	},
	{
		name:     "银行卡号",
		category: "数据泄露",
		severity: "critical",
		re:       regexp.MustCompile(`(?:^|[^\d])(?:62|4\d|5[1-5]|3[47])\d{13,17}(?:[^\d]|$)`),
		validate: validateLuhn,
	},
	{
		name:     "电子邮箱",
		category: "信息泄露",
		severity: "medium",
		re:       regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
	},
	{
		name:     "IPv4内网地址",
		category: "信息泄露",
		severity: "medium",
		re:       regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`),
	},
	{
		name:     "AWS密钥",
		category: "凭证泄露",
		severity: "critical",
		re:       regexp.MustCompile(`(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`),
	},
	{
		name:     "私钥标记",
		category: "凭证泄露",
		severity: "critical",
		re:       regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
	},
	{
		name:     "数据库连接串",
		category: "凭证泄露",
		severity: "critical",
		re:       regexp.MustCompile(`(?i)(?:mysql|postgres|mongodb|redis|mssql)://[^\s'"]+:[^\s'"]+@[^\s'"]+`),
	},
}

func detectPIIPatterns(text string) []map[string]any {
	var results []map[string]any

	for _, p := range piiPatterns {
		allMatches := p.re.FindAllString(text, 50)
		if len(allMatches) == 0 {
			continue
		}

		validMatches := make([]string, 0, len(allMatches))
		for _, m := range allMatches {
			m = strings.TrimSpace(m)
			if p.validate != nil && !p.validate(m) {
				continue
			}
			validMatches = append(validMatches, maskPII(m))
		}
		if len(validMatches) == 0 {
			continue
		}

		ctx := validMatches[0]
		if len(validMatches) > 1 {
			ctx = validMatches[0] + " 等" + strings.Repeat(".", 0)
		}

		results = append(results, map[string]any{
			"word":     p.name,
			"category": p.category,
			"severity": p.severity,
			"count":    len(validMatches),
			"context":  ctx,
			"contexts": validMatches,
			"is_regex": true,
		})
	}

	return results
}

func maskPII(s string) string {
	runes := []rune(s)
	if len(runes) <= 4 {
		return s
	}
	show := 4
	if len(runes) > 10 {
		show = 3
	}
	masked := make([]rune, len(runes))
	for i, r := range runes {
		if i < show || i >= len(runes)-show {
			masked[i] = r
		} else {
			masked[i] = '*'
		}
	}
	return string(masked)
}

func validateIDCard(s string) bool {
	digits := extractDigits(s)
	if len(digits) != 18 {
		return false
	}
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checkCodes := "10X98765432"
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(digits[i]-'0') * weights[i]
	}
	expected := checkCodes[sum%11]
	last := digits[17]
	if last >= 'a' && last <= 'z' {
		last -= 32
	}
	return last == expected
}

func validateLuhn(s string) bool {
	digits := extractDigits(s)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	odd := len(digits) % 2
	for i, d := range digits {
		n := int(d - '0')
		if i%2 == odd {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

func extractDigits(s string) string {
	var buf strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			buf.WriteRune(r)
		} else if r == 'X' || r == 'x' {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

type sensitiveWord struct {
	Word     string `json:"word"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

func (a *SensitiveWordAnalyzer) loadSensitiveWords() []sensitiveWord {
	if a.rules == nil {
		return nil
	}

	allRules, err := a.rules.GetAllRules()
	if err != nil {
		return nil
	}

	words := make([]sensitiveWord, 0)
	for key, data := range allRules {
		if !strings.HasPrefix(key, "lib/word/") {
			continue
		}
		var lib struct {
			Categories []struct {
				Name    string `json:"name"`
				Entries []struct {
					Word     string `json:"word"`
					Severity string `json:"severity"`
				} `json:"entries"`
			} `json:"categories"`
		}
		if err := json.Unmarshal(data, &lib); err != nil {
			continue
		}
		for _, cat := range lib.Categories {
			for _, entry := range cat.Entries {
				sev := entry.Severity
				if sev == "" {
					sev = "medium"
				}
				words = append(words, sensitiveWord{
					Word:     entry.Word,
					Category: cat.Name,
					Severity: sev,
				})
			}
		}
	}

	return words
}
