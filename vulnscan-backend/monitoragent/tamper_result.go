package monitoragent

import (
	"encoding/json"
	"unicode/utf8"

	"vulnscan-backend/sitemonitor/analyzer"
)

// BuildTamperResultJSON 输出前端 TamperDetail 所需结构（含首次基线、当前快照与 diff 列表）。
func BuildTamperResultJSON(snapshotJSON string, output *analyzer.Output, pageURL string) string {
	result := map[string]any{
		"tampered": false,
		"url":      pageURL,
	}

	var snap PageSnapshot
	if snapshotJSON != "" {
		_ = json.Unmarshal([]byte(snapshotJSON), &snap)
	}
	if snap.FinalURL != "" {
		result["url"] = snap.FinalURL
	} else if snap.URL != "" {
		result["url"] = snap.URL
	}
	if snap.StatusCode > 0 {
		result["status_code"] = snap.StatusCode
	}
	if snap.Title != "" {
		result["title"] = snap.Title
	}
	if snap.ContentHash != "" {
		result["content_hash"] = snap.ContentHash
	}
	if snap.VisibleText != "" || snap.RenderedHTML != "" {
		text := snap.VisibleText
		if text == "" {
			text = snap.RenderedHTML
		}
		result["visible_text_length"] = utf8.RuneCountInString(text)
	}

	if output != nil {
		result["tampered"] = output.HasIssue
		if output.Severity != "" {
			result["severity"] = output.Severity
		}
		if output.BaselineUpdate != nil {
			result["baseline_update"] = output.BaselineUpdate
			if output.BaselineUpdate.Action == "init" {
				result["is_first_run"] = true
				if output.BaselineUpdate.ContentHash != "" {
					result["content_hash"] = output.BaselineUpdate.ContentHash
				}
				if output.BaselineUpdate.Title != "" {
					result["title"] = output.BaselineUpdate.Title
				}
				if output.BaselineUpdate.StatusCode > 0 {
					result["status_code"] = output.BaselineUpdate.StatusCode
				}
				if output.BaselineUpdate.VisibleTextLength > 0 {
					result["visible_text_length"] = output.BaselineUpdate.VisibleTextLength
				}
			}
		}
		if output.DetailsJSON != "" {
			var details map[string]any
			if err := json.Unmarshal([]byte(output.DetailsJSON), &details); err == nil {
				if diffs, ok := details["diffs"].([]any); ok {
					result["diffs"] = diffs
				}
				if ev, ok := details["evidence"]; ok {
					result["evidence"] = ev
				}
				for _, key := range []string{"title", "status_code", "content_hash", "visible_text_length", "is_first_run"} {
					if v, ok := details[key]; ok && result[key] == nil {
						result[key] = v
					}
				}
				if cv, ok := details["cross_validation"]; ok {
					result["cross_validation"] = cv
				}
				if aa, ok := details["auto_accepted"]; ok {
					result["auto_accepted"] = aa
				}
				if nu, ok := details["likely_normal_update"]; ok {
					result["likely_normal_update"] = nu
				}
			}
		}
	}

	raw, _ := json.Marshal(result)
	return string(raw)
}
