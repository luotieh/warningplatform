package sitemonitor

import (
	"testing"

	"vulnscan-backend/model"
)

func TestShouldAutoCreateIncident_Disabled(t *testing.T) {
	exec := &model.MonitorExecution{
		HasIssue:   true,
		Status:     "success",
		Dimension:  "sensitive_word",
		ResultJSON: `{"has_hit":true,"total_matches":5}`,
	}
	cfg := model.JSONMap{"incident_auto_enabled": false, "incident_min_match_count": 1}
	if ShouldAutoCreateIncident(exec, cfg) {
		t.Fatal("expected false when auto disabled")
	}
}

func TestShouldAutoCreateIncident_SensitiveWordThreshold(t *testing.T) {
	exec := &model.MonitorExecution{
		HasIssue:   true,
		Status:     "success",
		Dimension:  "sensitive_word",
		ResultJSON: `{"has_hit":true,"total_matches":2}`,
	}
	cfg := model.JSONMap{"incident_auto_enabled": true, "incident_min_match_count": 3}
	if ShouldAutoCreateIncident(exec, cfg) {
		t.Fatal("expected false below min match count")
	}
	cfg["incident_min_match_count"] = 2
	if !ShouldAutoCreateIncident(exec, cfg) {
		t.Fatal("expected true at threshold")
	}
}

func TestShouldAutoCreateIncident_AvailabilityResponseTime(t *testing.T) {
	exec := &model.MonitorExecution{
		HasIssue:   true,
		Status:     "success",
		Dimension:  "availability",
		ResultJSON: `{"available":true,"response_time_ms":5000}`,
	}
	cfg := model.JSONMap{
		"incident_auto_enabled":         true,
		"incident_on_unavailable":       false,
		"incident_max_response_time_ms": 3000,
	}
	if !ShouldAutoCreateIncident(exec, cfg) {
		t.Fatal("expected true when response time exceeds max")
	}
	cfg["incident_max_response_time_ms"] = 10000
	if ShouldAutoCreateIncident(exec, cfg) {
		t.Fatal("expected false when response time below max and unavailable off")
	}
}

func TestMergeJSONMap_OverlayWins(t *testing.T) {
	base := model.JSONMap{"incident_auto_enabled": false, "cycle_minutes": 5}
	overlay := model.JSONMap{"incident_auto_enabled": true}
	out := mergeJSONMap(base, overlay)
	if !configBool(out, cfgIncidentAutoEnabled) {
		t.Fatal("overlay should win")
	}
	if intFromAny(out["cycle_minutes"]) != 5 {
		t.Fatal("base keys should remain")
	}
}
