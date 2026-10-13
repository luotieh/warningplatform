package service

import (
	"testing"
	"vulnscan-backend/evidence"
)

func TestReportNumbersAcceptsActualTimestampWithoutFractionalSeconds(t *testing.T) {
	entries := map[string]ReportEvidence{"E001": {Result: "北京时间=2026-10-11T20:03:53.6712+08:00"}}
	if err := validateReportNumbers("2026-10-11北京时间20:03:53发生接触", []string{"E001"}, entries); err != nil {
		t.Fatal(err)
	}
	if err := validateReportNumbers("20:03:52发生接触", []string{"E001"}, entries); err == nil {
		t.Fatal("invented seconds accepted")
	}
	if err := validateReportNumbers("53条命中", []string{"E002"}, map[string]ReportEvidence{"E002": {Result: "平均值53.6712"}}); err == nil {
		t.Fatal("measurement truncated to count")
	}
}

func TestReportNumbersDoesNotTreatThresholdAsPayloadMeasurement(t *testing.T) {
	entry := ReportEvidence{Finding: &evidence.Finding{Parameters: evidence.Parameters{Values: map[string]float64{"max_payload_bytes": 64}}}}
	if err := validateReportNumbers("载荷为64字节", []string{"E001"}, map[string]ReportEvidence{"E001": entry}); err == nil {
		t.Fatal("threshold promoted to measured bytes")
	}
}

func TestReportChineseCountsRemainBoundToCitedMaterial(t *testing.T) {
	entries := map[string]ReportEvidence{
		"E003": {Result: `五分钟桶次数={"12:30":14}; 平均间隔秒=0.12`},
		"E006": {Result: "历史传输接触=60条; 活跃天数=17"},
	}
	for _, tc := range []struct {
		text, ref string
		valid     bool
	}{
		{"14条命中全部集中在五分钟桶内，平均间隔0.12秒", "E003", true},
		{"命中集中在5分钟桶内", "E003", true},
		{"历史六十条传输接触，持续十七天", "E006", true},
		{"历史六十一条传输接触", "E006", false},
		{"六十条命中集中在五分钟桶内", "E003", false},
		{"历史传输接触持续十八天", "E006", false},
	} {
		err := validateReportNumbers(tc.text, []string{tc.ref}, entries)
		if (err == nil) != tc.valid {
			t.Errorf("%s: %v", tc.text, err)
		}
	}
}

func TestReportChineseInteger(t *testing.T) {
	for text, want := range map[string]int64{"零": 0, "两": 2, "十四": 14, "二十": 20, "一百零八": 108, "一千二百三十四": 1234, "一万零三": 10003, "二〇二六": 2026} {
		got, ok := reportChineseInteger(text)
		if !ok || got != want {
			t.Errorf("%s: %d %v", text, got, ok)
		}
	}
}
