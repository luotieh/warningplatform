package sitemonitor

import (
	"testing"

	"vulnscan-backend/model"
)

func TestApplyResultSemantics_Availability(t *testing.T) {
	exec := &model.MonitorExecution{}
	ar := &model.MonitorAgentResult{
		Dimension: "availability",
		Result:    `{"available":false,"status_code":503}`,
	}
	applyResultSemantics(nil, exec, ar)
	if !exec.HasIssue {
		t.Fatal("expected has_issue for unavailable site")
	}
}

func TestApplyResultSemantics_SensitiveWord(t *testing.T) {
	exec := &model.MonitorExecution{}
	ar := &model.MonitorAgentResult{
		Dimension: "sensitive_word",
		Result:    `{"has_hit":true,"total_matches":2,"matches":[]}`,
	}
	applyResultSemantics(nil, exec, ar)
	if !exec.HasIssue {
		t.Fatal("expected has_issue when has_hit=true")
	}
}
