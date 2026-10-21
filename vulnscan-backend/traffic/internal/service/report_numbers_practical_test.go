package service

import (
	"testing"
	"time"
	"vulnscan-backend/evidence"
)

func TestReportNumbersStructuredSources(t *testing.T) {
	at := time.Date(2026, 10, 21, 8, 44, 2, 631528000, time.UTC)
	entries := map[string]ReportEvidence{"O003": {
		Scope:        evidence.Scope{EndpointID: "tcp://104.21.57.117:443", AssetID: "asset-987654321"},
		Window:       &evidence.Window{Start: at, End: at.Add(time.Second)},
		Measurements: map[string]any{"payload_total_bytes": 132},
	}}
	for _, text := range []string{"104.21.57.117:443", "2026-10-21 16:44:02", "2026-10-21 08:44:02", "132字节"} {
		if err := validateReportNumbers(text, []string{"O003"}, entries); err != nil {
			t.Errorf("%s: %v", text, err)
		}
	}
	for _, text := range []string{"987654321字节", "16:59:59", "8443端口", "133字节"} {
		if err := validateReportNumbers(text, []string{"O003"}, entries); err == nil {
			t.Errorf("unsupported: %s", text)
		}
	}
}

func TestReportNumbersDoesNotBorrowZeroBytesFromRatio(t *testing.T) {
	entries := map[string]ReportEvidence{
		"F007": {Finding: &evidence.Finding{Measurements: evidence.Measurements{SampleCount: 2, Values: map[string]float64{"zero_payload_fraction": 1}}}},
		"O001": {Measurements: map[string]any{"payload_total_bytes": 0}},
	}
	if err := validateReportNumbers("总载荷0字节", []string{"F007"}, entries); err == nil {
		t.Fatal("ratio authorized total bytes")
	}
	if err := validateReportNumbers("总载荷0字节", []string{"O001"}, entries); err != nil {
		t.Fatal(err)
	}
}

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
