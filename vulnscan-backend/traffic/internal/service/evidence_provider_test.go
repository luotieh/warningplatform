package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func providerTestOptions(t *testing.T) EvidenceQueryOptions {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "evidence-pipeline-v2.1", "input-field-map.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c []EvidenceFieldContract
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return EvidenceQueryOptions{Contracts: c}
}
func providerTestEvent(t *testing.T, s *store.MemoryStore, id, asset, address, device string, at time.Time) EvidenceSnapshot {
	t.Helper()
	ctx := context.Background()
	_, err := s.CreateAsset(domain.Asset{ID: asset, Address: address, Status: 1})
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{"device_id": device, "src_ip": address, "dst_ip": "198.51.100.20", "src_port": "51000", "dst_port": "80", "protocol": "tcp", "app": map[string]any{"http_url": "http://fixture.test/path", "http_method": "GET"}, "ioc": map[string]any{"ioc_type": "ip", "ioc_value": "198.51.100.20"}, "first_time": at.Format(time.RFC3339Nano), "last_time": at.Format(time.RFC3339Nano)}
	data, _ := json.Marshal(raw)
	_, err = s.CreateEvent(domain.Event{EventID: id, Context: string(data), Observables: []domain.IOC{{Type: "ip", Value: "198.51.100.20"}}, CreatedAt: at, LastSeenAt: &at})
	if err != nil {
		t.Fatal(err)
	}
	hit, err := s.InsertHit(ctx, store.Hit{ID: id + "-hit", DedupKey: id + "-hit", EventID: id, OccurredAt: at, Raw: data})
	if err != nil {
		t.Fatal(err)
	}
	snap := EvidenceSnapshot{EventID: id, Version: 1, Sources: []string{id}, Watermark: hit.Sequence, Count: 1, Context: raw}
	for _, r := range []struct {
		kind, key string
		v         any
	}{{"segment", id, EventSegment{EventID: id, Published: 1}}, {"snapshot", snapshotKey(id, 1), snap}} {
		b, _ := json.Marshal(r.v)
		if err = s.PutAggregateRecord(ctx, store.AggregateRecord{Kind: r.kind, Key: r.key, Value: b}); err != nil {
			t.Fatal(err)
		}
	}
	return snap
}
func providerTestStoreDigest(t *testing.T, s *store.MemoryStore) string {
	t.Helper()
	ctx := context.Background()
	records, _ := s.AggregateRecords(ctx, "snapshot", "", 100)
	segments, _ := s.AggregateRecords(ctx, "segment", "", 100)
	return digest([]any{s.ListEvents(), s.ListAssets(), records, segments})
}

func TestEvidenceProviderReadOnlyRepeatAndExecution(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "asset", "192.0.2.10", "sensor", at)
	before := providerTestStoreDigest(t, s)
	o := providerTestOptions(t)
	b, a, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", o)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Valid || len(a.Queries) != 7 || len(a.Fields) == 0 {
		t.Fatal("missing audit", a.Valid, len(a.Queries))
	}
	repeat, _, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", o)
	if err != nil || repeat.InputDigest != b.InputDigest {
		t.Fatal("nondeterministic", err)
	}
	if before != providerTestStoreDigest(t, s) {
		t.Fatal("business store changed")
	}
	result, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal(err)
	}
	if result.Evidence.Pipeline.Completed != 82 {
		t.Fatal("incomplete catalog")
	}
	for _, in := range b.Inputs.Request.Inputs {
		if in.Network.Complete || in.HTTP.Complete || in.HTTP.Records[0].ResponseVerified || in.HTTP.Records[0].TransactionID != "" {
			t.Fatal("sample promoted to complete transaction")
		}
	}
	if len(b.Inputs.Manifest.PhaseOne.Contacts) != 0 {
		t.Fatal("invented independent contacts")
	}
}

func TestEvidenceProviderBoundedCrossEventAssetAndHistory(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "asset", "192.0.2.10", "sensor", at)
	// A separately owned peer event has the same IOC and overlapping time.
	providerTestEvent(t, s, "peer", "peer-asset", "192.0.2.11", "peer-sensor", at)
	// History has explicit source, device and IOC fields, independent of a report.
	prior := at.Add(-24 * time.Hour)
	m := map[string]any{"device_id": "sensor", "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "ioc": map[string]any{"ioc_type": "ip", "ioc_value": "198.51.100.20"}, "first_time": prior.Format(time.RFC3339), "last_time": prior.Format(time.RFC3339)}
	raw, _ := json.Marshal(m)
	_, _ = s.CreateEvent(domain.Event{EventID: "history", Context: string(raw), CreatedAt: prior, LastSeenAt: &prior})
	bad := prior.Add(-time.Hour)
	m["device_id"] = "other-sensor"
	m["first_time"], m["last_time"] = bad.Format(time.RFC3339), bad.Format(time.RFC3339)
	raw, _ = json.Marshal(m)
	_, _ = s.CreateEvent(domain.Event{EventID: "wrong-device", Context: string(raw), CreatedAt: bad, LastSeenAt: &bad})
	b, a, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Candidates) != 1 || len(b.Inputs.Request.Hits) != 2 || len(b.Inputs.Request.Groups) != 1 {
		t.Fatal("cross-event observations missing")
	}
	if len(b.History.Rows) != 1 || b.History.Rows[0].EventID != "history" {
		t.Fatal("history binding", b.History.Rows)
	}
	if !b.History.Truncated || b.Inputs.Request.Groups[0].Complete {
		t.Fatal("claimed full network or campaign coverage")
	}
	result, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal(err)
	}
	if result.Evidence.Pipeline.Completed != 82 {
		t.Fatal("catalog")
	}
}

func TestEvidenceProviderWindowLimitsCancellationAndFailure(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	snap := providerTestEvent(t, s, "current", "asset", "192.0.2.10", "sensor", at)
	o := providerTestOptions(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := PrepareEvidenceFromPlatform(ctx, s, "current", o); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	o.Start = at.Add(-time.Second)
	if _, _, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", o); err == nil || !strings.Contains(err.Error(), "outside_published") {
		t.Fatal(err)
	}
	defaults, err := providerOptions(providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := (TrafficDataProvider{s}).Load(context.Background(), snap, evidence.AnalysisWindow{Start: at.Add(-time.Second), End: at}, defaults)
	if err != nil || len(rows) != 0 {
		t.Fatal("exclusive end violated", err)
	}
	rows, err = (TrafficDataProvider{s}).Load(context.Background(), snap, evidence.AnalysisWindow{Start: at, End: at.Add(time.Nanosecond)}, defaults)
	if err != nil || len(rows) != 1 {
		t.Fatal("inclusive start violated", err)
	}
	defaults.MaxBytes = 1
	if _, err = (TrafficDataProvider{s}).Load(context.Background(), snap, evidence.AnalysisWindow{Start: at, End: at.Add(time.Second)}, defaults); err == nil {
		t.Fatal("byte budget bypass")
	}
	failure := failedProviderReader{EvidenceReader: s}
	_, audit, err := PrepareEvidenceFromPlatform(context.Background(), failure, "current", providerTestOptions(t))
	if err == nil || len(audit.Queries) == 0 || audit.Queries[len(audit.Queries)-1].Status != "failed" {
		t.Fatal("read failure disguised as empty")
	}
}

type failedProviderReader struct{ store.EvidenceReader }

func (failedProviderReader) HistoryCandidates(context.Context, store.HistoryQuery) ([]domain.Event, error) {
	return nil, errors.New("injected history read failure")
}

func TestEvidenceProviderRejectsForgedSourceAndAmbiguousAsset(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "asset", "192.0.2.10", "sensor", at)
	b, _, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	b.Inputs.Request.Inputs[0].HTTP.Records[0].SourceID = "foreign-hit"
	b.Coverage = PreparedInputCoverage(b.Inputs)
	b.Seal()
	if b.Validate() == nil {
		t.Fatal("foreign protocol source accepted")
	}
	_, createErr := s.CreateAsset(domain.Asset{ID: "ambiguous", Address: "::ffff:192.0.2.10", Status: 1})
	if createErr != nil {
		t.Fatal(createErr)
	}
	amb, _, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(amb.Inputs.Request.Hits) != 0 || amb.Inputs.Manifest.UnresolvedHits != 1 {
		t.Fatal("ambiguous address forced to asset")
	}
}

func TestEvidenceProviderTrustedRegistryExactScope(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "asset", "192.0.2.10", "sensor", at)
	o := providerTestOptions(t)
	b, _, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", o)
	if err != nil {
		t.Fatal(err)
	}
	scope := b.Inputs.Request.Inputs[0].Scope
	reference := EvidenceSourceRegistry{Version: "reviewed-test-import", Entries: []EvidenceSourceEntry{{ID: "service-registry", Authority: "isolated-test-admin", ApprovedAt: at.Add(-time.Hour), Input: evidence.Input{Scope: scope, Window: &evidence.AnalysisWindow{Start: at.Add(-time.Hour), End: at.Add(time.Hour)}, Network: &evidence.NetworkData{Provenance: evidence.Provenance{Verified: true, Complete: true, Version: "catalog-1", SourceIDs: []string{"catalog-source"}}, Services: []evidence.Service{{Port: 80, Protocol: "http"}}, ServicesVerified: true}}}}}
	put := func() {
		raw, _ := json.Marshal(reference)
		if err := s.PutAggregateRecord(context.Background(), store.AggregateRecord{Kind: "evidence_sources", Key: "active", Value: raw}); err != nil {
			t.Fatal(err)
		}
	}
	put()
	b, a, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", o)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Inputs.Request.Inputs[0].Network.ServicesVerified || b.Inputs.Manifest.SourceRegistryVersion == "" {
		t.Fatal("trusted configured reference ignored", a.Diagnostics)
	}
	reference.Entries[0].Input.Scope.AssetID = "other-asset"
	put()
	b, _, err = PrepareEvidenceFromPlatform(context.Background(), s, "current", o)
	if err != nil {
		t.Fatal(err)
	}
	if b.Inputs.Request.Inputs[0].Network.ServicesVerified {
		t.Fatal("cross-asset reference attached")
	}
	reference.Entries[0].Authority = ""
	put()
	_, a, err = PrepareEvidenceFromPlatform(context.Background(), s, "current", o)
	if err == nil || a.Queries[len(a.Queries)-1].Status != "failed" {
		t.Fatal("untrusted reference silently accepted")
	}
}

func TestEvidenceProviderSupplementalCannotReplaceCoreOrSnapshot(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	snap := providerTestEvent(t, s, "current", "asset", "192.0.2.10", "sensor", at)
	b, _, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	extra := SnapshotSupplementalInputs{EventID: "current", SnapshotVersion: 1, Version: "saved-enrichment-1", Inputs: []evidence.Input{{Scope: b.Inputs.Request.Inputs[0].Scope, Window: b.Inputs.Request.Inputs[0].Window, Network: &evidence.NetworkData{Connections: []evidence.Connection{{SourceID: "forged"}}}}}}
	put := func() {
		raw, _ := json.Marshal(extra)
		_ = s.PutAggregateRecord(context.Background(), store.AggregateRecord{Kind: "evidence_inputs", Key: snapshotKey("current", 1), Value: raw})
	}
	put()
	record, _, err := (ContextDataProvider{s}).LoadSupplemental(context.Background(), snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := preprocessProviderSupplemental(&record, snap); err == nil {
		t.Fatal("supplemental replaced core observations")
	}
	extra.Inputs = nil
	extra.SnapshotVersion = 2
	put()
	record, _, err = (ContextDataProvider{s}).LoadSupplemental(context.Background(), snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := preprocessProviderSupplemental(&record, snap); err == nil {
		t.Fatal("wrong snapshot accepted")
	}
}

func TestEvidenceProviderStoredHistoryReachesExistingC01(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "asset", "192.0.2.10", "sensor", at)
	base, _ := s.GetEvent("current")
	for i, id := range []string{"prior-one", "prior-two"} {
		prior := at.Add(-time.Duration(i+1) * 24 * time.Hour)
		c := decodeEventContext(base.Context)
		c["first_time"], c["last_time"] = prior.Format(time.RFC3339), prior.Format(time.RFC3339)
		raw, _ := json.Marshal(c)
		_, err := s.CreateEvent(domain.Event{EventID: id, Context: string(raw), CreatedAt: prior, LastSeenAt: &prior})
		if err != nil {
			t.Fatal(err)
		}
	}
	b, _, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range result.Evidence.PhaseOne.Result.Units {
		if u.ID == "C01" && u.Status == "observed" && u.Score == evidence.DefaultPhaseOneConfig().Points["C01"] {
			found = true
		}
	}
	if !found {
		t.Fatal("stored exact history did not reach unchanged C01", result.Evidence.PhaseOne.Result.Units)
	}
}
