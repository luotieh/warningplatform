package domain

import (
	"testing"
	"time"
)

func TestReportAvailabilityAndAttemptState(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		status    string
		version   int
		ctx, want string
	}{
		{"pending", 2, `{"ai_probability":55}`, "completed"},
		{"failed", 1, `{}`, "completed"},
		{"processing", 1, `{}`, "completed"},
		{"failed", 0, `{}`, "failed"},
		{"pending", 0, `{}`, "pending"},
		{"processing", 1, `{"analysis_job_state":"running","analysis_started_at":"2000-01-01T00:00:00Z"}`, "completed"},
		{"processing", 0, `{"analysis_job_state":"failed"}`, "failed"},
	} {
		e := Event{EventStatus: tc.status, AnalysisVersion: tc.version, Context: tc.ctx}
		if got := AnalysisState(e, now); got != tc.want {
			t.Fatalf("%+v got %s", tc, got)
		}
	}
}
