package monitoragent

import (
	"encoding/json"

	"vulnscan-backend/sitemonitor/analyzer"
)

// BuildSensitiveWordResultJSON 输出前端 SensitiveWordDetail 所需结构。
func BuildSensitiveWordResultJSON(snapshotJSON string, output *analyzer.Output) string {
	result := map[string]any{
		"has_hit":       false,
		"total_matches": 0,
		"matches":       []any{},
		"text_length":   0,
	}

	var snap PageSnapshot
	_ = json.Unmarshal([]byte(snapshotJSON), &snap)
	if snap.URL != "" || snap.FinalURL != "" {
		result["url"] = firstNonEmpty(snap.FinalURL, snap.URL)
	}

	if output != nil && output.DetailsJSON != "" {
		var details map[string]any
		if err := json.Unmarshal([]byte(output.DetailsJSON), &details); err == nil {
			if v, ok := details["has_hit"].(bool); ok {
				result["has_hit"] = v
			} else if output.HasIssue {
				result["has_hit"] = true
			}
			if v, ok := details["total_matches"].(float64); ok {
				result["total_matches"] = int(v)
			}
			if v, ok := details["total_matches"].(int); ok {
				result["total_matches"] = v
			}
			if v, ok := details["text_length"].(float64); ok {
				result["text_length"] = int(v)
			}
			if v, ok := details["text_length"].(int); ok {
				result["text_length"] = v
			}
			if u, ok := details["url"].(string); ok && u != "" {
				result["url"] = u
			}
			if html, ok := details["page_evidence_html"].(string); ok && html != "" {
				result["page_evidence_html"] = html
			}
			if matches, ok := details["matches"].([]any); ok {
				normalized := make([]map[string]any, 0, len(matches))
				for _, item := range matches {
					m, ok := item.(map[string]any)
					if !ok {
						continue
					}
					normalized = append(normalized, normalizeSensitiveWordMatch(m))
				}
				result["matches"] = normalized
				if len(normalized) > 0 {
					result["has_hit"] = true
				}
			}
		}
	} else if output != nil {
		result["has_hit"] = output.HasIssue
	}

	raw, _ := json.Marshal(result)
	return string(raw)
}

func normalizeSensitiveWordMatch(m map[string]any) map[string]any {
	out := map[string]any{
		"word":     m["word"],
		"category": m["category"],
		"severity": m["severity"],
		"count":    m["count"],
	}
	if ctx, ok := m["context"].(string); ok && ctx != "" {
		out["context"] = ctx
	}
	if html, ok := m["evidence_html"].(string); ok {
		out["evidence_html"] = html
	}
	if list, ok := m["contexts"].([]any); ok && len(list) > 0 {
		out["contexts"] = list
		if _, has := out["context"]; !has {
			if s, ok := list[0].(string); ok {
				out["context"] = s
			}
		}
	} else if ctxList, ok := m["contexts"].([]string); ok && len(ctxList) > 0 {
		out["contexts"] = ctxList
		if _, has := out["context"]; !has {
			out["context"] = ctxList[0]
		}
	}
	return out
}
