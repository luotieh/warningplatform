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
