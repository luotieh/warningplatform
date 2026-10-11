package service

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
)

func TestReportRecordedDatagramLengthCannotRepairTruncatedBytes(t *testing.T) {
	raw, err := os.ReadFile("testdata/report_recorded_datagrams.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 2 {
		t.Fatal("recorded fixture missing")
	}
	for n, row := range rows {
		reportVerifyDatagram(row)
		v, known := nestedMap(row, "raw_packet")["capture_truncated"].(bool)
		if n == 0 && (!known || v) {
			t.Fatal("complete recorded DNS datagram rejected")
		}
		if n == 0 && asString(nestedMap(row, "raw_packet")["payload_hex"]) == "" {
			t.Fatal("actual DNS transport payload collapsed into an empty preview")
		}
		if n == 1 && known && !v {
			t.Fatal("missing IPv4 bytes manufactured as complete")
		}
	}
}

func TestDNSConnectionJoinRequiresEveryIdentityAndTimeCondition(t *testing.T) {
	at := time.Date(2026, 10, 8, 11, 9, 9, 0, time.UTC)
	row := ReportMaterialObservation{HitID: "current", Time: at.Add(503 * time.Millisecond), Protocol: "tcp", Scope: evidence.Scope{AssetID: "asset", DeviceID: "device", EndpointID: "tcp://104.21.60.213:443"}, Application: json.RawMessage(`{"tls_sni":"www.lshau.sbs"}`)}
	h := ReportHistory{Rows: []ReportHistoryRow{{EventID: "prior", DeviceID: "device", AllAssetIDs: []string{"asset"}, First: at, Last: at, Application: map[string]any{"dns_query": "www.lshau.sbs", "dns_answers": []any{"104.21.60.213"}}}}}
	valid := reportDNSConnectionEvidence([]ReportMaterialObservation{row}, &h)
	if len(valid) != 1 || !strings.Contains(valid[0].Result, "0.503000") || len(valid[0].SourceIDs) != 2 {
		t.Fatal("valid exact join lost", valid)
	}
	for _, change := range []func(*ReportMaterialObservation){func(r *ReportMaterialObservation) { r.Scope.DeviceID = "other" }, func(r *ReportMaterialObservation) { r.Scope.AssetID = "other" }, func(r *ReportMaterialObservation) { r.Time = at.Add(-time.Second) }, func(r *ReportMaterialObservation) { r.Time = at.Add(6 * time.Minute) }, func(r *ReportMaterialObservation) { r.Application = json.RawMessage(`{"tls_sni":"other.test"}`) }} {
		copy := row
		change(&copy)
		if len(reportDNSConnectionEvidence([]ReportMaterialObservation{copy}, &h)) != 0 {
			t.Fatal("unrelated activity joined")
		}
	}
}

func TestReportNumbersUseCitedScopeInsteadOfAnotherEvidence(t *testing.T) {
	entries := map[string]ReportEvidence{"E001": {Result: "已保存49条命中；12个目的端口；跨度3.012000秒"}, "E002": {Result: "已保存999条命中"}}
	if err := validateReportNumbers("E001记录49条命中和12个端口，跨度3.012秒", []string{"E001"}, entries); err != nil {
		t.Fatal(err)
	}
	if validateReportNumbers("记录999条命中", []string{"E001"}, entries) == nil {
		t.Fatal("number from unrelated scope accepted")
	}
}

func TestReportWeakContactCannotReachHighProbability(t *testing.T) {
	_, _, b := reportTestBundle(t)
	a := validReportAssessment(b)
	p := 85
	a.Probability = &p
	entries := map[string]ReportEvidence{}
	for _, e := range b.Entries {
		entries[e.ID] = e
	}
	if validateHighReportProbability(a, entries) == nil {
		t.Fatal("weak contact promoted to high probability")
	}
}
