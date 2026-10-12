package service

import (
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

func TestReportIOCIdentityDoesNotPromoteResolverObservables(t *testing.T) {
	event := domain.Event{Observables: []domain.IOC{{Type: "ip", Value: "218.2.2.2"}, {Type: "ip", Value: "180.104.100.118"}, {Type: "domain", Value: "lsax.org"}}}
	c := map[string]any{"ioc": map[string]any{"ioc_type": "domain", "ioc_value": "lsax.org"}}
	terms := historyIOCs(event, c)
	if len(terms) != 1 || terms[0].Type != "domain" || terms[0].Value != "lsax.org" {
		t.Fatal("resolver became IOC", terms)
	}
	start := time.Date(2026, 10, 9, 9, 39, 24, 0, time.UTC)
	out := SnapshotEvidenceInput{}
	out.Request.Inputs = []evidence.Input{{Scope: evidence.Scope{AssetID: "asset", EndpointID: "udp://218.2.2.2:53"}, Window: &evidence.AnalysisWindow{Start: start, End: start.Add(time.Second)}, DNS: &evidence.DNSData{Records: []evidence.DNSRecord{{Domain: "lsax.org"}}}}}
	history := ReportHistory{Version: reportHistoryVersion, Status: "available", Start: start.AddDate(0, 0, -30), End: start, MatchIOCs: []domain.IOC{{Type: "ip", Value: "218.2.2.2"}, {Type: "domain", Value: "lsax.org"}}, Rows: []ReportHistoryRow{{EventID: "other-domain", First: start.Add(-time.Hour), Last: start.Add(-time.Hour), AllAssetIDs: []string{"asset"}, ActivityIOCs: []domain.IOC{{Type: "domain", Value: "4936.net"}}}, {EventID: "same-domain", First: start.Add(-2 * time.Hour), Last: start.Add(-2 * time.Hour), AllAssetIDs: []string{"asset"}, ActivityIOCs: []domain.IOC{{Type: "domain", Value: "lsax.org"}}}}}
	applyPlatformHistory(&out, EvidenceSnapshot{EventID: "current", Version: 1}, &history)
	h := out.Request.Inputs[0].PlatformHistory
	if h.IOC != "lsax.org" || h.Events[0].IOC == h.IOC || h.Events[1].IOC != h.IOC {
		t.Fatal("incorrect domain recurrence binding", h)
	}
}

func TestReportProjectionBypassesLegacyClippingWithoutChangingLegacy(t *testing.T) {
	snap := EvidenceSnapshot{EventID: "large", Version: 1, Count: 1, Context: map[string]any{}, Manifest: map[string]any{"audit_rows": strings.Repeat("x", 10000)}, Evidence: []map[string]any{{"payload_text": strings.Repeat("x", 20000), "payload_hex": strings.Repeat("f", 20000)}}}
	if _, err := evidenceContextFromSnapshot(snap, nil); err == nil {
		t.Fatal("legacy fixture no longer exercises its cap")
	}
	if _, err := projectReportEvidence(snap, SnapshotFactEvaluation{}, ReportSemanticEvaluation{}); err != nil {
		t.Fatal("report still depends on shared clipping", err)
	}
}

func TestReportReviewInferenceBoundaries(t *testing.T) {
	entries := map[string]ReportEvidence{"E001": {Finding: &evidence.Finding{Measurements: evidence.Measurements{Values: map[string]float64{"small_payload_fraction": 1, "dns_records": 31}}}}}
	for _, text := range []string{"全部小包，无载荷传输迹象", "观测窗口仅1天，无跨日持续行为", "确认观测数据完整性", "短时DNS通联，无异常规模", "将域名加入白名单", "历史89条持续通联"} {
		if validateReportBoundaries(text, []string{"E001"}, entries) == nil {
			t.Errorf("unsupported inference accepted: %s", text)
		}
	}
	if err := validateReportBoundaries("先核对本资产的业务任务，核验一致后考虑限定资产、协议与有效期的白名单例外", []string{"E001"}, entries); err != nil {
		t.Fatal(err)
	}
	entries["E002"] = ReportEvidence{Result: "完成原文核验的去重报文4份，核验应用载荷总字节=0（只覆盖这些报文）"}
	if err := validateReportBoundaries("这4份保存报文无载荷", []string{"E002"}, entries); err != nil {
		t.Fatal(err)
	}
}

func TestReportPayloadCountsDeduplicatePhysicalRecords(t *testing.T) {
	payload := 37
	at := time.Now()
	scope := evidence.Scope{AssetID: "asset", DeviceID: "device", EndpointID: "udp://218.2.2.2:53"}
	rows := []ReportMaterialObservation{{HitID: "a", PhysicalPacketID: "same", Time: at, Scope: scope, PayloadBytes: &payload}, {HitID: "b", PhysicalPacketID: "same", Time: at, Scope: scope, PayloadBytes: &payload}}
	result := reportMaterialEvidence(rows)[0].Result
	if !strings.Contains(result, "核验应用载荷总字节=37") || !strings.Contains(result, "去重报文1份") {
		t.Fatal("physical payload counted twice", result)
	}
}
