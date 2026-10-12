package service

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
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

type reportHistoryHitCounter struct {
	store.Store
	Reads int
}

func (s *reportHistoryHitCounter) HitPage(ctx context.Context, q store.HitQuery) ([]store.Hit, error) {
	s.Reads++
	return s.Store.HitPage(ctx, q)
}

func TestReportHistoricalDNSReadsOneBatchAndRejectsContradictoryAnswer(t *testing.T) {
	raw, err := os.ReadFile("testdata/report_recorded_datagrams.json")
	if err != nil {
		t.Fatal(err)
	}
	var saved []map[string]any
	if json.Unmarshal(raw, &saved) != nil {
		t.Fatal("recorded fixture invalid")
	}
	m := saved[0]
	m["device_id"] = "recorded-device"
	at, err := time.Parse(time.RFC3339Nano, asString(nestedMap(m, "raw_packet")["capture_time"]))
	if err != nil {
		t.Fatal(err)
	}
	svc, _, _ := reportTestBundle(t)
	encoded, _ := json.Marshal(m)
	hit, err := svc.Store.InsertHit(context.Background(), store.Hit{ID: "recorded-dns", DedupKey: "recorded-dns", EventID: "prior-dns", OccurredAt: at, Raw: encoded})
	if err != nil {
		t.Fatal(err)
	}
	counter := &reportHistoryHitCounter{Store: svc.Store}
	svc.Store = counter
	snap := EvidenceSnapshot{Watermark: hit.Sequence, Evidence: []map[string]any{{"app": map[string]any{"tls_sni": "www.lshau.sbs"}}}}
	h := ReportHistory{End: at.Add(503 * time.Millisecond), Rows: []ReportHistoryRow{{EventID: "prior-dns", DeviceID: "recorded-device", SourceAddress: "218.4.4.4", DestinationAddress: "180.104.100.118", First: at, Last: at, Application: nestedMap(m, "app")}}}
	svc.verifyReportHistoricalDNS(context.Background(), snap, &h)
	if counter.Reads != 1 || h.RawDNSStatus != "verified_nearby_dns" || len(h.Rows[0].VerifiedDNSHitIDs) != 1 {
		t.Fatalf("not a verified single batch: %+v reads=%d", h, counter.Reads)
	}
	h.Rows[0].VerifiedDNSHitIDs = nil
	h.Rows[0].Application["dns_answers"] = []any{"192.0.2.99"}
	svc.verifyReportHistoricalDNS(context.Background(), snap, &h)
	if len(h.Rows[0].VerifiedDNSHitIDs) != 0 || h.RawDNSStatus != "history_raw_dns_not_verified" {
		t.Fatal("contradictory parsed answer accepted", h)
	}
}

func TestReportSemanticDNSUsesActualRootFrameInsteadOfNestedPreview(t *testing.T) {
	raw, err := os.ReadFile("testdata/report_recorded_datagrams.json")
	if err != nil {
		t.Fatal(err)
	}
	var saved []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&saved) != nil {
		t.Fatal("invalid fixture")
	}
	m := saved[0]
	nestedMap(m, "raw_packet")["request"] = map[string]any{"payload_hex": ""}
	reportVerifyDatagram(m)
	input := evidence.Input{Scope: evidence.Scope{AssetID: "asset", DeviceID: "device", EndpointID: "udp://218.4.4.4:53"}, DNS: &evidence.DNSData{Records: []evidence.DNSRecord{{SourceID: "recorded", Domain: "www.lshau.sbs"}}}}
	out := SnapshotEvidenceInput{}
	collectSnapshotSemanticObservation(&out, &input, store.Hit{ID: "recorded"}, m, nil)
	if len(out.SemanticObservations) != 1 || !out.SemanticObservations[0].Complete {
		t.Fatal("root complete DNS lost to nested preview", out.SemanticObservations)
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

func TestReportNeutralHistoryInterpretationKeepsFullContextAndBinding(t *testing.T) {
	scope := evidence.Scope{AssetID: "asset", EndpointID: "tls://target:443"}
	explanation := strings.Repeat("经来源核验的历史关联解释。", 40)
	b := ReportEvidenceBundle{SelectedIDs: []string{"E001"}, Entries: []ReportEvidence{
		{ID: "E001", FactID: "F_HISTORY_RECURRENCE", Scope: scope, Finding: &evidence.Finding{}},
		{ID: "E002", Scope: scope, SourceIDs: []string{"prior-event", "raw-hit"}, Semantic: &evidence.SemanticFinding{Slot: evidence.SlotKey{ID: "R06"}, ExplanationOnly: true, SemanticItem: evidence.SemanticItem{Judgement: "neutral", Explanation: explanation, FactRefs: []string{"F_HISTORY_RECURRENCE"}, Quotes: []evidence.SemanticQuote{{MaterialID: "history", Excerpt: "同资产同IOC"}}}}},
		{ID: "E003", Scope: scope, Semantic: &evidence.SemanticFinding{Slot: evidence.SlotKey{ID: "S15"}, ExplanationOnly: true}},
	}}
	prompt, err := evidenceReportPrompt(domain.Event{EventID: "current"}, preparedReportInput{}, b, "")
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal([]byte(prompt), &input); err != nil {
		t.Fatal(err)
	}
	contexts := input["validated_history_interpretations"].([]any)
	if len(contexts) != 1 {
		t.Fatal("history dropped or diagnostics promoted", contexts)
	}
	row := contexts[0].(map[string]any)
	if row["result"] != explanation || row["id"] != nil || row["context_only"] != true || row["fact_report_ids"].([]any)[0] != "E001" {
		t.Fatal("history binding/content changed", row)
	}
	if len(input["source_catalog"].(map[string]any)) != 2 {
		t.Fatal("history provenance clipped")
	}
}

// Optional verification against the read-only production journal. This checks
// actual projection size, never substitutes for model/report acceptance.
func TestReportRecordedProjectionBudget(t *testing.T) {
	path := os.Getenv("REPORT_AUDIT_JOURNAL")
	if path == "" {
		t.Skip("production journal not supplied")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		Kind  string          `json:"kind"`
		Group string          `json:"group"`
		Value json.RawMessage `json:"value"`
	}
	facts := map[string]SnapshotFactEvaluation{}
	semantics := map[string]ReportSemanticEvaluation{}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r row
		if json.Unmarshal(line, &r) != nil {
			t.Fatal("invalid journal")
		}
		if r.Kind == "evidence_result" {
			var f SnapshotFactEvaluation
			if json.Unmarshal(r.Value, &f) != nil {
				t.Fatal("invalid fact record")
			}
			if strings.HasPrefix(f.Manifest.AdapterVersion, "report-") && f.Manifest.AdapterVersion >= facts[r.Group].Manifest.AdapterVersion {
				facts[r.Group] = f
			}
		}
		if r.Kind == "semantic_result" {
			var s ReportSemanticEvaluation
			if json.Unmarshal(r.Value, &s) != nil {
				t.Fatal("invalid semantic record")
			}
			if strings.HasPrefix(s.AdapterVersion, "snapshot-semantic-adapter-1.3") && s.AdapterVersion >= semantics[r.Group].AdapterVersion {
				semantics[r.Group] = s
			}
		}
	}
	for id, f := range facts {
		event := domain.Event{EventID: id}
		snap := EvidenceSnapshot{EventID: id, Version: f.Manifest.SnapshotVersion, Count: f.Manifest.DeclaredHits, Context: map[string]any{}}
		b := buildReportEvidence(event, snap, f, semantics[id])
		prompt, err := evidenceReportPrompt(event, preparedReportInput{}, b, "")
		if err != nil {
			if directory := os.Getenv("REPORT_AUDIT_OUTPUT"); directory != "" {
				encoded, _ := json.Marshal(b)
				_ = os.WriteFile(directory+"/"+id+"-projection-bundle.json", encoded, 0600)
			}
			if f.Manifest.AdapterVersion == reportSnapshotAdapterVersion {
				t.Errorf("%s: %v", id, err)
			} else {
				t.Logf("%s historical_adapter=%s fails current projection; current-version production computation required: %v", id, f.Manifest.AdapterVersion, err)
			}
			continue
		}
		t.Logf("%s actual_fact_adapter=%s semantics=%s selected=%d bytes=%d estimated_tokens=%d", id, f.Manifest.AdapterVersion, semantics[id].AdapterVersion, len(b.SelectedIDs), len(prompt), estimateTokens(prompt))
	}
}
