package analyzer

import (
	"html"
	"strings"
)

const (
	defaultContextRadius = 80
	maxEvidenceRunes     = 120_000
)

type wordHit struct {
	word     string
	severity string
}

func extractSensitiveWordEvidence(source, word, severity string) (context string, contexts []string, evidenceHTML string) {
	word = strings.TrimSpace(word)
	if source == "" || word == "" {
		return "", nil, ""
	}

	lowerSrc := strings.ToLower(source)
	lowerWord := strings.ToLower(word)
	if !strings.Contains(lowerSrc, lowerWord) {
		return "", nil, ""
	}

	runes := []rune(source)
	lowerRunes := []rune(lowerSrc)
	wordRunes := []rune(lowerWord)

	var snippets []string
	seen := make(map[string]struct{})
	startAt := 0
	for startAt < len(lowerRunes) {
		idx := indexRunes(lowerRunes[startAt:], wordRunes)
		if idx < 0 {
			break
		}
		abs := startAt + idx
		snippet := snippetRunes(runes, abs, len(wordRunes), defaultContextRadius)
		if _, ok := seen[snippet]; !ok && snippet != "" {
			seen[snippet] = struct{}{}
			snippets = append(snippets, snippet)
		}
		startAt = abs + len(wordRunes)
		if len(snippets) >= 5 {
			break
		}
	}

	if len(snippets) == 0 {
		return "", nil, ""
	}
	context = snippets[0]
	evidenceHTML = buildHighlightedFullTextHTML(source, []wordHit{{word: word, severity: severity}})
	return context, snippets, evidenceHTML
}

// buildPageEvidenceHTML 在全文范围内高亮所有命中词（用于可滚动证据区）。
func buildPageEvidenceHTML(source string, hits []wordHit) string {
	return buildHighlightedFullTextHTML(source, hits)
}

func buildHighlightedFullTextHTML(source string, hits []wordHit) string {
	source = truncateRunes(source, maxEvidenceRunes)
	if source == "" || len(hits) == 0 {
		return ""
	}
	runes := []rune(source)
	lower := []rune(strings.ToLower(source))
	marks := make([]string, len(runes))

	for _, hit := range hits {
		word := strings.TrimSpace(hit.word)
		if word == "" {
			continue
		}
		wordRunes := []rune(strings.ToLower(word))
		markClass := severityMarkClass(hit.severity)
		rank := severityRank(hit.severity)
		startAt := 0
		for startAt < len(lower) {
			idx := indexRunes(lower[startAt:], wordRunes)
			if idx < 0 {
				break
			}
			abs := startAt + idx
			for i := abs; i < abs+len(wordRunes) && i < len(marks); i++ {
				if marks[i] == "" || rank > severityRankFromMarkClass(marks[i]) {
					marks[i] = markClass
				}
			}
			startAt = abs + len(wordRunes)
		}
	}
	return renderMarkedRunes(runes, marks)
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "\n…（内容过长，已截断）"
}

func renderMarkedRunes(runes []rune, marks []string) string {
	var b strings.Builder
	flushPlain := func(text string) {
		if text != "" {
			b.WriteString(html.EscapeString(text))
		}
	}
	var plain strings.Builder
	flushMark := func(class string, text string) {
		if text == "" {
			return
		}
		b.WriteString(`<mark class="`)
		b.WriteString(class)
		b.WriteString(`">`)
		b.WriteString(html.EscapeString(text))
		b.WriteString(`</mark>`)
	}
	currentClass := ""
	var marked strings.Builder
	for i, r := range runes {
		cls := ""
		if i < len(marks) {
			cls = marks[i]
		}
		if cls != currentClass {
			if currentClass == "" {
				flushPlain(plain.String())
				plain.Reset()
			} else {
				flushMark(currentClass, marked.String())
				marked.Reset()
			}
			currentClass = cls
		}
		if currentClass == "" {
			plain.WriteRune(r)
		} else {
			marked.WriteRune(r)
		}
	}
	if currentClass == "" {
		flushPlain(plain.String())
	} else {
		flushMark(currentClass, marked.String())
	}
	return b.String()
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return 3
	case "low":
		return 1
	default:
		return 2
	}
}

func severityRankFromMarkClass(class string) int {
	switch class {
	case "sw-hit sw-hit--high":
		return 3
	case "sw-hit sw-hit--low":
		return 1
	default:
		return 2
	}
}

func snippetRunes(runes []rune, matchStart, wordLen, radius int) string {
	start := matchStart - radius
	if start < 0 {
		start = 0
	}
	end := matchStart + wordLen + radius
	if end > len(runes) {
		end = len(runes)
	}
	s := strings.TrimSpace(string(runes[start:end]))
	if start > 0 {
		s = "…" + s
	}
	if end < len(runes) {
		s += "…"
	}
	return s
}

func buildHighlightedEvidenceHTML(source, word, severity string, radius int) string {
	word = strings.TrimSpace(word)
	if source == "" || word == "" {
		return ""
	}
	runes := []rune(source)
	lowerRunes := []rune(strings.ToLower(source))
	wordRunes := []rune(word)
	lowerWordRunes := []rune(strings.ToLower(word))

	matchIdx := indexRunes(lowerRunes, lowerWordRunes)
	if matchIdx < 0 {
		return ""
	}
	snippetStart := matchIdx - radius
	if snippetStart < 0 {
		snippetStart = 0
	}
	snippetEnd := matchIdx + len(wordRunes) + radius
	if snippetEnd > len(runes) {
		snippetEnd = len(runes)
	}
	snippetRunes := runes[snippetStart:snippetEnd]
	lowerSnippet := []rune(strings.ToLower(string(snippetRunes)))

	markClass := severityMarkClass(severity)
	var b strings.Builder
	if snippetStart > 0 {
		b.WriteString("…")
	}
	pos := 0
	for pos < len(snippetRunes) {
		rel := indexRunes(lowerSnippet[pos:], lowerWordRunes)
		if rel < 0 {
			b.WriteString(html.EscapeString(string(snippetRunes[pos:])))
			break
		}
		abs := pos + rel
		b.WriteString(html.EscapeString(string(snippetRunes[pos:abs])))
		b.WriteString(`<mark class="`)
		b.WriteString(markClass)
		b.WriteString(`">`)
		b.WriteString(html.EscapeString(string(snippetRunes[abs : abs+len(wordRunes)])))
		b.WriteString(`</mark>`)
		pos = abs + len(wordRunes)
	}
	if snippetEnd < len(runes) {
		b.WriteString("…")
	}
	return b.String()
}

func severityMarkClass(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "sw-hit sw-hit--high"
	case "low":
		return "sw-hit sw-hit--low"
	default:
		return "sw-hit sw-hit--medium"
	}
}

func indexRunes(haystack, needle []rune) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func combineSearchText(snap *snapshotData) string {
	var parts []string
	if t := strings.TrimSpace(snap.Title); t != "" {
		parts = append(parts, t)
	}
	if v := strings.TrimSpace(snap.VisibleText); v != "" {
		parts = append(parts, v)
	} else if raw := strings.TrimSpace(snap.RenderedHTML); raw != "" {
		parts = append(parts, raw)
	}
	return strings.Join(parts, "\n")
}
