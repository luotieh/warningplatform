package config

import "testing"

func TestReportCapacityLimits(t *testing.T) {
	o, err := (ReportOptions{}).Resolve(6000)
	if err != nil || o.InputTokens != 20000 || o.OutputTokens != 6000 || o.ContextTokens != 0 {
		t.Fatal(o, err)
	}
	for _, bad := range []ReportOptions{{InputTokens: -1}, {OutputTokens: -1}, {ContextTokens: -1}, {SafetyTokens: -1}, {InputTokens: 6000, OutputTokens: 6000, ContextTokens: 11000}, {InputTokens: 6000, OutputTokens: 6000, ContextTokens: 12000, SafetyTokens: 1}} {
		if _, err := bad.Resolve(6000); err == nil {
			t.Fatal("accepted invalid config", bad)
		}
	}
	o, err = (ReportOptions{InputTokens: 6000, OutputTokens: 6000, ContextTokens: 13000, SafetyTokens: 1000}).Resolve(6000)
	if err != nil || o.InputTokens != 6000 {
		t.Fatal(o, err)
	}
}

func TestReportEnvironmentStrictAndSeparate(t *testing.T) {
	t.Setenv("REPORT_INPUT_TOKEN_LIMIT", "8000")
	t.Setenv("REPORT_OUTPUT_TOKEN_LIMIT", "7000")
	t.Setenv("REPORT_LOG_ENABLED", "false")
	o, err := LoadReportOptions()
	if err != nil || o.InputTokens != 8000 || o.OutputTokens != 7000 || o.LogEnabled == nil || *o.LogEnabled {
		t.Fatal(o, err)
	}
	t.Setenv("REPORT_INPUT_TOKEN_LIMIT", "invalid")
	if _, err = LoadReportOptions(); err == nil {
		t.Fatal("bad input limit ignored")
	}
}
