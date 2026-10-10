package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type evidenceReadCounter struct {
	store.Store
	hitPages, revisionBatches, singleRevisions, snapshotReads, registryReads int
}

func (s *evidenceReadCounter) HitPage(ctx context.Context, q store.HitQuery) ([]store.Hit, error) {
	s.hitPages++
	return s.Store.HitPage(ctx, q)
}
func (s *evidenceReadCounter) HitRevisions(ctx context.Context, ids []string, w int64) (map[string]json.RawMessage, error) {
	s.revisionBatches++
	return s.Store.HitRevisions(ctx, ids, w)
}
func (s *evidenceReadCounter) HitRevision(ctx context.Context, id string, w int64) (json.RawMessage, error) {
	s.singleRevisions++
	return s.Store.HitRevision(ctx, id, w)
}
func (s *evidenceReadCounter) AggregateRecord(ctx context.Context, k, id string) (store.AggregateRecord, bool, error) {
	if k == "snapshot" {
		s.snapshotReads++
	}
	return s.Store.AggregateRecord(ctx, k, id)
}
func (s *evidenceReadCounter) ListAssets() []domain.Asset {
	s.registryReads++
	return s.Store.ListAssets()
}

func (s *evidenceReadCounter) ListAssetsContext(ctx context.Context) ([]domain.Asset, error) {
	s.registryReads++
	return s.Store.ListAssetsContext(ctx)
}

func evidenceAdapterFixture(t *testing.T, n int) (Services, EvidenceSnapshot, []domain.Asset) {
	t.Helper()
	svc := Services{Store: store.NewMemoryStore()}
	asset, err := svc.Store.CreateAsset(domain.Asset{ID: "asset-a", Address: "192.0.2.1", Name: "registered host", Status: 1})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	var id string
	for i := 0; i < n; i++ {
		m := testHit(fmt.Sprintf("evidence-%d", i), base.Add(time.Duration(i)*time.Minute))
		m["raw_packet"].(map[string]any)["capture_truncated"] = false
		if i%2 == 1 {
			m["src_ip"], m["dst_ip"] = m["dst_ip"], m["src_ip"]
			m["src_port"], m["dst_port"] = m["dst_port"], m["src_port"]
		}
		r, err := svc.ProcessLyEvent(context.Background(), m)
		if err != nil {
			t.Fatal(err)
		}
		id = asString(r["deepsoc_event_id"])
	}
	if err := svc.RebuildAggregation(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	snap, err := svc.EvidenceSnapshot(context.Background(), id, 0)
	if err != nil {
		t.Fatal(err)
	}
	return svc, snap, []domain.Asset{asset}
}

func TestSnapshotAdapterUsesCommittedHitsNotRepresentatives(t *testing.T) {
	svc, snap, assets := evidenceAdapterFixture(t, 12)
	if len(snap.Evidence) >= 12 {
		t.Fatalf("fixture must have compressed representatives: %d", len(snap.Evidence))
	}
	counter := &evidenceReadCounter{Store: svc.Store}
	svc.Store = counter
	input, err := svc.SnapshotEvidenceInput(context.Background(), snap, assets, DefaultSnapshotEvidenceOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(input.Request.Hits) != 12 || len(input.Request.Inputs) != 1 || input.Manifest.BoundHits != 12 || input.Manifest.Coverage != "complete" {
		t.Fatalf("wrong complete input: %+v", input.Manifest)
	}
	for _, h := range input.Request.Hits {
		if h.Scope.AssetID != assets[0].ID || h.Scope.EndpointID != "udp://192.0.2.2:53" || h.Scope.DeviceID != "node-a" {
			t.Fatalf("reverse direction not canonical: %+v", h.Scope)
		}
	}
	engine, _ := evidence.NewEngine(evidence.DefaultConfig())
	result, err := engine.Evaluate(context.Background(), input.Request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 || result.Findings[0].Status != evidence.Observed || result.Findings[0].Measurements.SampleCount != 12 {
		t.Fatalf("not evaluated on full hits: %+v", result.Findings)
	}
	if counter.singleRevisions != 0 || counter.snapshotReads != 0 || counter.registryReads != 0 {
		t.Fatalf("adapter reread shared sources: %+v", counter)
	}
}

func TestSnapshotReportReusesSnapshotAndVersionedResult(t *testing.T) {
	svc, snap, _ := evidenceAdapterFixture(t, 8)
	counter := &evidenceReadCounter{Store: svc.Store}
	svc.Store = counter
	ev := mustEvent(t, svc, snap.EventID)
	raw, err := svc.PrepareReportEvidence(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "F_BEACON_PERIODIC") || !strings.Contains(raw, `"status":"observed"`) {
		t.Fatalf("computed facts absent: %s", raw)
	}
	if len([]rune(raw)) > 6000 || counter.snapshotReads != 1 || counter.registryReads != 1 {
		t.Fatalf("projection/batched sources: %d %+v", len([]rune(raw)), counter)
	}
	reads := counter.hitPages
	raw, err = svc.PrepareReportEvidence(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if counter.hitPages != reads || !strings.Contains(raw, `"cache_hit":true`) {
		t.Fatalf("repeat report rescanned hits: %+v", counter)
	}
	results, err := svc.Store.AggregateRecords(context.Background(), "evidence_result", snap.EventID, 0)
	if err != nil || len(results) != 1 {
		t.Fatalf("full evidence not retained: %v %d", err, len(results))
	}
	var saved SnapshotFactEvaluation
	if err := json.Unmarshal(results[0].Value, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Result == nil || len(saved.Result.Findings[0].SourceIDs) != 8 {
		t.Fatal("source references dropped from complete result")
	}
	assets := svc.Store.ListAssets()
	svc.Store.UpdateAsset(assets[0].ID, map[string]any{"status": 0})
	raw, err = svc.PrepareReportEvidence(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "asset_registry_unavailable") || strings.Contains(raw, `"status":"observed"`) {
		t.Fatal("disabled registry reused stale fact")
	}
}

func TestSnapshotAdapterBindingAndInputBudgets(t *testing.T) {
	svc, snap, assets := evidenceAdapterFixture(t, 8)
	for _, tc := range []struct {
		name   string
		assets []domain.Asset
		opts   SnapshotEvidenceOptions
		reason string
		noRead bool
	}{
		{"registry absent", nil, DefaultSnapshotEvidenceOptions(), "asset_registry_unavailable", true},
		{"both peers registered", append(append([]domain.Asset(nil), assets...), domain.Asset{ID: "asset-b", Address: "192.0.2.2", Status: 1}), DefaultSnapshotEvidenceOptions(), "unresolved_asset_endpoint_binding", false},
		{"duplicate ownership", append(append([]domain.Asset(nil), assets...), domain.Asset{ID: "another", Address: "192.0.2.1", Status: 1}), DefaultSnapshotEvidenceOptions(), "unresolved_asset_endpoint_binding", false},
		{"hit limit", assets, SnapshotEvidenceOptions{MaxHits: 7, MaxRawBytes: 1 << 20}, "snapshot_hit_budget_exceeded", true},
		{"byte limit", assets, SnapshotEvidenceOptions{MaxHits: 8, MaxRawBytes: 1}, "snapshot_input_budget_exceeded", false},
		{"explicit empty", assets, SnapshotEvidenceOptions{Facts: []evidence.FactID{}, MaxHits: 8, MaxRawBytes: 1 << 20}, "not_requested", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counter := &evidenceReadCounter{Store: svc.Store}
			copy := svc
			copy.Store = counter
			result, err := copy.EvaluateSnapshotFacts(context.Background(), snap, tc.assets, tc.opts, evidence.DefaultConfig())
			if err != nil || result.Reason != tc.reason || result.Result != nil {
				t.Fatalf("wrong downgrade: %v %+v", err, result)
			}
			if tc.noRead && counter.hitPages != 0 {
				t.Fatal("unneeded hit query")
			}
		})
	}
	bad := snap
	bad.Count++
	if _, err := svc.SnapshotEvidenceInput(context.Background(), bad, assets, DefaultSnapshotEvidenceOptions()); err == nil {
		t.Fatal("membership mismatch accepted")
	}
	opts := DefaultSnapshotEvidenceOptions()
	opts.Facts = []evidence.FactID{"invented"}
	if _, err := svc.SnapshotEvidenceInput(context.Background(), snap, assets, opts); err == nil {
		t.Fatal("unknown fact accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.SnapshotEvidenceInput(ctx, snap, assets, DefaultSnapshotEvidenceOptions()); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestSnapshotScopeNeverTrustsIOCOrClientVerification(t *testing.T) {
	assets := []domain.Asset{{ID: "network", Address: "192.0.2.0/24", Status: 1}}
	m := map[string]any{"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "src_port": json.Number("5000"), "dst_port": json.Number("443"), "protocol": "tcp", "device_id": "sensor", "asset_id": "client-claim", "verified": true, "victim_target": "198.51.100.1", "ioc_value": "192.0.2.1"}
	scope, _, _, ok := snapshotScope(m, assets)
	if !ok || scope.AssetID != "network@192.0.2.1" {
		t.Fatalf("wrong trusted registry identity: %+v %v", scope, ok)
	}
	m["src_ip"] = "192.0.2.3"
	scope2, _, _, ok := snapshotScope(m, assets)
	if !ok || scope2.AssetID == scope.AssetID {
		t.Fatal("CIDR members collapsed")
	}
	m["dst_ip"] = "192.0.2.2"
	if _, _, _, ok := snapshotScope(m, assets); ok {
		t.Fatal("IOC or direction used to choose between two registered peers")
	}
	for _, v := range []any{nil, json.Number("-1"), json.Number("1.5"), json.Number("18446744073709551616"), true} {
		if _, ok := strictUint(v); ok {
			t.Fatalf("invalid counter accepted: %v", v)
		}
	}
	if n, ok := strictUint(json.Number("9007199254740993")); !ok || n != 9007199254740993 {
		t.Fatal("integer precision lost")
	}
}

func TestSnapshotAdapterRevisionWatermarkAndBatchRead(t *testing.T) {
	svc, snap, assets := evidenceAdapterFixture(t, 8)
	ctx := context.Background()
	page, err := svc.Store.HitPage(ctx, store.HitQuery{Sources: snap.Sources, Watermark: snap.Watermark, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range page {
		var m map[string]any
		json.Unmarshal(h.Raw, &m)
		m["packets"] = 4
		b, _ := json.Marshal(m)
		w, err := svc.Store.InsertHitRevision(ctx, h.ID, 1, b)
		if err != nil {
			t.Fatal(err)
		}
		snap.RevisionWatermark = w
	}
	for _, h := range page {
		var m map[string]any
		json.Unmarshal(h.Raw, &m)
		m["packets"] = 99
		b, _ := json.Marshal(m)
		if _, err := svc.Store.InsertHitRevision(ctx, h.ID, 2, b); err != nil {
			t.Fatal(err)
		}
	}
	counter := &evidenceReadCounter{Store: svc.Store}
	svc.Store = counter
	input, err := svc.SnapshotEvidenceInput(ctx, snap, assets, DefaultSnapshotEvidenceOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range input.Request.Hits {
		if h.Packets == nil || *h.Packets != 4 {
			t.Fatal("newer revision leaked or historical revision ignored")
		}
	}
	if counter.revisionBatches != 1 || counter.singleRevisions != 0 {
		t.Fatalf("N+1 revision reads: %+v", counter)
	}
}

func TestSnapshotProtocolAdapterDoesNotInventProofs(t *testing.T) {
	scope := evidence.Scope{AssetID: "a", EndpointID: "tcp://198.51.100.1:443", DeviceID: "d"}
	input := evidence.Input{Scope: scope}
	h := store.Hit{ID: "real-hit", OccurredAt: time.Now()}
	m := map[string]any{"packets": json.Number("3"), "bytes": json.Number("500"), "transaction_id": "tx", "app": map[string]any{"http_url": "https://brand.com.evil.test/login", "http_method": "POST", "http_body_sample": "password=secret", "dns_query": "example.test", "dns_rcode": json.Number("3")}, "raw_packet": map[string]any{"payload_hex": "00ff"}}
	adaptSnapshotProtocols(&input, h, m, "198.51.100.1", 443, true)
	if input.HTTP == nil || input.HTTP.Records[0].Fields != nil || !input.HTTP.Records[0].Truncated || input.HTTP.Records[0].BodyLength != nil || input.HTTP.BrandsVerified {
		t.Fatal("sample promoted to full/verified HTTP")
	}
	if input.Network.Connections[0].PayloadBytes == nil || *input.Network.Connections[0].PayloadBytes != 2 || input.Network.Connections[0].ProtocolParsed {
		t.Fatal("flow volume or protocol label promoted to parsed fact")
	}
	if input.DNS == nil || !input.DNS.Records[0].RCodeKnown || input.DNS.Records[0].RCode != 3 {
		t.Fatal("actual parsed DNS code lost")
	}
	if input.History != nil || input.TLS != nil || input.Authorizations != nil || input.Corroboration != nil || len(input.Baselines) != 0 {
		t.Fatal("missing external evidence fabricated")
	}
}

func TestReportProjectionKeepsImmutableSnapshot(t *testing.T) {
	_, snap, _ := evidenceAdapterFixture(t, 8)
	before, _ := json.Marshal(snap)
	if _, err := evidenceContextFromSnapshot(snap, map[string]any{"algorithm_evidence": map[string]any{"status": "unavailable"}}); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(snap)
	if string(before) != string(after) {
		t.Fatal("report projection mutated shared snapshot")
	}
}

func TestSnapshotAdapterMissingPacketsAndUnknownCaptureRemainMissing(t *testing.T) {
	for _, field := range []string{"packets", "capture_truncated"} {
		t.Run(field, func(t *testing.T) {
			svc, snap, assets := evidenceAdapterFixture(t, 8)
			page, _ := svc.Store.HitPage(context.Background(), store.HitQuery{Sources: snap.Sources, Watermark: snap.Watermark, Limit: 500})
			var m map[string]any
			json.Unmarshal(page[0].Raw, &m)
			if field == "packets" {
				delete(m, field)
			} else {
				delete(m["raw_packet"].(map[string]any), field)
			}
			b, _ := json.Marshal(m)
			w, err := svc.Store.InsertHitRevision(context.Background(), page[0].ID, 1, b)
			if err != nil {
				t.Fatal(err)
			}
			snap.RevisionWatermark = w
			result, err := svc.EvaluateSnapshotFacts(context.Background(), snap, assets, DefaultSnapshotEvidenceOptions(), evidence.DefaultConfig())
			if err != nil || result.Result == nil || result.Result.Findings[0].Status != evidence.Missing {
				t.Fatalf("missing %s silently fabricated: %v %+v", field, err, result)
			}
		})
	}
}

func TestSnapshotAdapterReadsManyHitsOnceForAllSelectedFacts(t *testing.T) {
	st := store.NewMemoryStore()
	svc := Services{Store: st}
	ctx := context.Background()
	asset := domain.Asset{ID: "a", Address: "192.0.2.1", Status: 1}
	base := time.Now().UTC().Add(-time.Hour)
	var watermark int64
	for i := 0; i < 501; i++ {
		m := testHit(fmt.Sprint(i), base.Add(time.Duration(i)*time.Second))
		m["raw_packet"].(map[string]any)["capture_truncated"] = false
		h, _, why := normalizeHit(m, time.Now())
		if why != "" {
			t.Fatal(why)
		}
		h.EventID = "event"
		inserted, err := st.InsertHit(ctx, h)
		if err != nil {
			t.Fatal(err)
		}
		watermark = inserted.Sequence
	}
	snap := EvidenceSnapshot{EventID: "event", Version: 1, Sources: []string{"event"}, Watermark: watermark, Count: 501}
	counter := &evidenceReadCounter{Store: st}
	svc.Store = counter
	options := DefaultSnapshotEvidenceOptions()
	options.Facts = evidence.SupportedFacts()
	evaluation, err := svc.EvaluateSnapshotFacts(ctx, snap, []domain.Asset{asset}, options, evidence.DefaultConfig())
	if err != nil || evaluation.Manifest.LoadedHits != 501 || evaluation.Result == nil {
		t.Fatalf("load failed: %v %+v", err, evaluation.Manifest)
	}
	if counter.hitPages != 3 || counter.singleRevisions != 0 || counter.revisionBatches != 0 {
		t.Fatalf("queries scaled with fact count: %+v", counter)
	}
	if len(evaluation.Result.Findings) != 59 {
		t.Fatalf("selected rules dropped: %d", len(evaluation.Result.Findings))
	}
}

func TestAnalysisPipelineActuallySendsComputedSnapshotFacts(t *testing.T) {
	svc, snap, _ := evidenceAdapterFixture(t, 8)
	counter := &evidenceReadCounter{Store: svc.Store}
	svc.Store = counter
	var reportPrompt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		reply := "OK"
		for _, message := range body.Messages {
			if message.Role == "user" && message.Content != "health" {
				reportPrompt = message.Content
				reply = acceptedReportResponse(t, message.Content)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": reply}}}})
	}))
	defer server.Close()
	svc.LLM = &client.LLMClient{BaseURL: server.URL, Model: "fixture", HTTP: server.Client()}
	if err := svc.RunAgentWorkflow(context.Background(), snap.EventID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reportPrompt, "selected_evidence") || !strings.Contains(reportPrompt, "F_BEACON_PERIODIC") || !strings.Contains(reportPrompt, `"status":"observed"`) {
		t.Fatalf("new engine absent from actual model call: %s", reportPrompt)
	}
	if strings.Contains(reportPrompt, "evidence_result_key") || strings.Contains(reportPrompt, "registry_version") {
		t.Fatal("internal cache fingerprints leaked to model")
	}
	if counter.registryReads != 1 || counter.snapshotReads != 1 {
		t.Fatalf("report and adapter did not share source reads: %+v", counter)
	}
	ev := mustEvent(t, svc, snap.EventID)
	if ev.AnalysisVersion != 1 {
		t.Fatal("analysis did not finish")
	}
	manifest, ok, err := svc.Store.AggregateRecord(context.Background(), "report_manifest", snapshotKey(snap.EventID, snap.Version))
	if err != nil || !ok || !strings.Contains(string(manifest.Value), "evidence_result_key") {
		t.Fatal("report lost link to complete fact result")
	}
}

func TestSnapshotHTTPPathNeedsActualSchemeProof(t *testing.T) {
	app := map[string]any{"http_url": "/login?next=1", "http_host": "example.test", "http_method": "POST"}
	packet := map[string]any{"payload_text": "POST /login?next=1 HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n"}
	if got := snapshotHTTPURL(app, packet); got != "http://example.test/login?next=1" {
		t.Fatalf("documented path not reconstructed: %s", got)
	}
	if got := snapshotHTTPURL(app, nil); got != "" {
		t.Fatal("scheme guessed from host/path")
	}
	app["http_host"] = "conflicting.test"
	if got := snapshotHTTPURL(app, packet); got != "" {
		t.Fatal("conflicting wire and parsed app accepted")
	}
	app["http_url"] = "https://example.test/login"
	if got := snapshotHTTPURL(app, nil); got != "https://example.test/login" {
		t.Fatal("actual absolute URL lost")
	}
}
