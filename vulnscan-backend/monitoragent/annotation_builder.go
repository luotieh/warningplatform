package monitoragent

import (
	"encoding/json"
	"strings"

	"vulnscan-backend/sitemonitor/analyzer"
)

// BuildAnnotationsFromOutput 从分析结果中提取标注信息，供标注截图使用。
func BuildAnnotationsFromOutput(dimension string, output *analyzer.Output) []IssueAnnotation {
	if output == nil || !output.HasIssue || output.DetailsJSON == "" {
		return nil
	}

	var details map[string]any
	if err := json.Unmarshal([]byte(output.DetailsJSON), &details); err != nil {
		return nil
	}

	switch dimension {
	case "sensitive_word":
		return buildSensitiveWordAnnotations(details)
	case "blacklink":
		return buildBlacklinkAnnotations(details)
	case "tamper":
		return buildTamperAnnotations(details)
	default:
		return nil
	}
}

func buildSensitiveWordAnnotations(details map[string]any) []IssueAnnotation {
	matches, ok := details["matches"].([]any)
	if !ok || len(matches) == 0 {
		return nil
	}

	keywords := make([]string, 0, len(matches))
	for _, item := range matches {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		word, _ := m["word"].(string)
		if word != "" {
			keywords = append(keywords, word)
		}
	}

	if len(keywords) == 0 {
		return nil
	}

	return []IssueAnnotation{{
		Type:     "text",
		Keywords: keywords,
		Label:    "敏感词",
	}}
}

func buildBlacklinkAnnotations(details map[string]any) []IssueAnnotation {
	var annotations []IssueAnnotation

	if links, ok := details["blacklink_matches"].([]any); ok && len(links) > 0 {
		urls := make([]string, 0, len(links))
		for _, item := range links {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			url, _ := m["url"].(string)
			if url != "" {
				urls = append(urls, url)
			}
		}
		if len(urls) > 0 {
			annotations = append(annotations, IssueAnnotation{
				Type:     "link",
				Keywords: urls,
				Label:    "暗链",
			})
		}
	}

	if findings, ok := details["backdoor_findings"].([]any); ok && len(findings) > 0 {
		for _, item := range findings {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			src, _ := m["src"].(string)
			if src != "" {
				annotations = append(annotations, IssueAnnotation{
					Type:     "selector",
					Selector: `script[src*="` + src + `"]`,
					Label:    "后门脚本",
				})
			}
		}
	}

	return annotations
}

func buildTamperAnnotations(details map[string]any) []IssueAnnotation {
	var annotations []IssueAnnotation

	if diffs, ok := details["diffs"].([]any); ok {
		for _, d := range diffs {
			dm, ok := d.(map[string]any)
			if !ok {
				continue
			}
			if dtype, _ := dm["type"].(string); dtype == "injected_elements" {
				if elems, ok := dm["elements"].([]any); ok {
					for _, item := range elems {
						m, ok := item.(map[string]any)
						if !ok {
							continue
						}
						if src, _ := m["src"].(string); src != "" {
							annotations = append(annotations, IssueAnnotation{
								Type:     "selector",
								Selector: `script[src*="` + src + `"]`,
								Label:    "外部注入脚本",
							})
						}
					}
				}
			}
		}
	}

	if ev, ok := details["evidence"].(map[string]any); ok {
		if curHTML, _ := ev["current_html"].(string); curHTML != "" {
			keywords := extractInsertedTexts(curHTML)
			if len(keywords) > 0 {
				annotations = append(annotations, IssueAnnotation{
					Type:     "text",
					Keywords: keywords,
					Label:    "篡改内容",
				})
			}
		}
	}

	return annotations
}

func extractInsertedTexts(html string) []string {
	const openTag = `<ins class="tp-ins">`
	const closeTag = `</ins>`
	var results []string
	seen := make(map[string]bool)
	rem := html
	for len(results) < 20 {
		start := strings.Index(rem, openTag)
		if start < 0 {
			break
		}
		rem = rem[start+len(openTag):]
		end := strings.Index(rem, closeTag)
		if end < 0 {
			break
		}
		text := strings.TrimSpace(rem[:end])
		text = unescapeBasicHTML(text)
		if len([]rune(text)) >= 4 && !seen[text] {
			if len([]rune(text)) > 100 {
				text = string([]rune(text)[:100])
			}
			results = append(results, text)
			seen[text] = true
		}
		rem = rem[end+len(closeTag):]
	}
	return results
}

func unescapeBasicHTML(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", `"`)
	s = strings.ReplaceAll(s, "&#39;", "'")
	return s
}
