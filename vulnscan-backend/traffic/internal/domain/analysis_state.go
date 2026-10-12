package domain

import (
	"encoding/json"
	"time"
)

// AnalysisState keeps a published report separate from the latest update attempt.
func AnalysisState(e Event, now time.Time) string {
	var c map[string]any
	_ = json.Unmarshal([]byte(e.Context), &c)
	hasReport := e.AnalysisVersion > 0 || c["report_published"] == true
	// A usable report remains generated while its replacement is queued,
	// running or failed. Only first-time generation affects list status.
	if hasReport {
		return "completed"
	}
	state, _ := c["analysis_job_state"].(string)
	if state == "running" {
		started := ParseEventTime(c["analysis_started_at"])
		if started.IsZero() || now.Sub(started) > 2*time.Hour {
			state = "failed"
		}
	}
	if state == "" {
		switch e.EventStatus {
		case "processing":
			state = "running"
		case "failed", "llm_config_required":
			state = "failed"
		}
	}
	if state == "failed" {
		return "failed"
	}
	if state == "running" {
		return "processing"
	}
	if e.EventStatus == "round_finished" {
		return "completed"
	}
	return "pending"
}
