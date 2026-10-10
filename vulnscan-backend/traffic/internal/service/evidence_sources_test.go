package service

import (
	"context"
	"encoding/json"
	"errors"
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

func sourceFixture(t *testing.T) (Services, EvidenceSnapshot, EvidenceSourceRegistry) {
	t.Helper()
	svc, snap, assets := evidenceAdapterFixture(t, 8)
	in, err := svc.SnapshotEvidenceInput(context.Background(), snap, assets, DefaultSnapshotEvidenceOptions())
	if err != nil {
		t.Fatal(err)
	}
	i := in.Request.Inputs[0]
	p := evidence.Provenance{Verified: true, Complete: true, Version: "audit-v1", SourceIDs: []string{"independent-reviewed-history-export"}}
	r := EvidenceSourceRegistry{Version: "sources-v1", Entries: []EvidenceSourceEntry{{ID: "history", Authority: "independent-human-review", ApprovedAt: time.Now().UTC(), Input: evidence.Input{Scope: i.Scope, Window: &evidence.AnalysisWindow{Start: i.Window.Start.Add(-time.Hour), End: i.Window.End.Add(time.Hour)}, History: &evidence.HistoryData{Provenance: p, AsOf: i.Window.End.Add(time.Minute), LookbackStart: i.Window.Start.AddDate(0, 0, -31), Endpoint: i.Scope.EndpointID}}}}}
	return svc, snap, r
}

func TestSourcesAutomaticallyFeedSharedReportAndInvalidateCache(t *testing.T) {
	svc, snap, r := sourceFixture(t)
	ctx := context.Background()
	raw, _ := json.Marshal(r)
	if err := svc.ImportEvidenceSources(ctx, raw); err != nil {
		t.Fatal(err)
	}
	counted := &evidenceReadCounter{Store: svc.Store}
	svc.Store = counted
	event := mustEvent(t, svc, snap.EventID)
	p, err := svc.prepareReportInput(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if p.Evaluation.Manifest.SourceRegistryVersion == "" || counted.hitPages != 2 {
		t.Fatalf("source producer not shared/bounded: %+v", p.Evaluation.Manifest)
	}
	found := false
	for _, f := range p.Evaluation.Result.Findings {
		if f.FactID == "F_DST_NOVELTY" {
			found = f.Status == evidence.Observed
		}
	}
	if !found {
		t.Fatal("verified covered history did not reach actual rule")
	}
	pages := counted.hitPages
	p, err = svc.prepareReportInput(ctx, event)
	if err != nil || !p.Evaluation.CacheHit || counted.hitPages != pages {
		t.Fatal("warm report reread hits")
	}
	// Keep claimed version unchanged: cache must depend on actual source data.
	r.Entries[0].Input.History.Events = []evidence.HistoryEvent{{ID: "previous-independent-event", Adjudication: "unreviewed", Time: r.Entries[0].Input.Window.Start.Add(-time.Hour), AssetID: r.Entries[0].Input.Scope.AssetID, Endpoint: r.Entries[0].Input.Scope.EndpointID}}
	raw, _ = json.Marshal(r)
	if err := svc.ImportEvidenceSources(ctx, raw); err != nil {
		t.Fatal(err)
	}
	p, err = svc.prepareReportInput(ctx, event)
	if err != nil || p.Evaluation.CacheHit {
		t.Fatal("source change retained stale cache")
	}
	for _, f := range p.Evaluation.Result.Findings {
		if f.FactID == "F_DST_NOVELTY" && f.Status != evidence.NotObserved {
			t.Fatal("changed historical source ignored")
		}
	}
	audits, err := svc.Store.AggregateRecords(ctx, "evidence_source_audit", "", 10)
	if err != nil || len(audits) != 2 {
		t.Fatal("source changes lost previous audit version")
	}
}

func TestSourceImportRejectsUntrustedOverlappingAndFutureProofs(t *testing.T) {
	_, _, base := sourceFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*EvidenceSourceRegistry)
	}{
		{"unverified", func(r *EvidenceSourceRegistry) { r.Entries[0].Input.History.Verified = false }},
		{"model adjudication", func(r *EvidenceSourceRegistry) {
			h := r.Entries[0].Input.History
			h.Events = []evidence.HistoryEvent{{ID: "old", Time: h.LookbackStart.Add(time.Hour), Adjudication: "malicious", AdjudicationID: "model-output", AdjudicationSource: "llm"}}
		}},
		{"overlap", func(r *EvidenceSourceRegistry) {
			e := r.Entries[0]
			e.ID = "duplicate-scope"
			r.Entries = append(r.Entries, e)
		}},
		{"snapshot proof", func(r *EvidenceSourceRegistry) { r.Entries[0].Input.History.CurrentStage = "c2" }},
		{"normal baseline absent", func(r *EvidenceSourceRegistry) {
			r.Entries[0].Input.Baselines = []evidence.Baseline{{Provenance: r.Entries[0].Input.History.Provenance, FactID: "F_RATE_BURST"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var r EvidenceSourceRegistry
			_ = json.Unmarshal(raw, &r)
			tc.change(&r)
			if validateEvidenceSources(r) == nil {
				t.Fatal("unsafe source accepted")
			}
		})
	}
}

func TestSourceHistoryCoverageGapRemainsMissing(t *testing.T) {
	svc, snap, r := sourceFixture(t)
	r.Entries[0].Input.History.AsOf = r.Entries[0].Input.Window.Start
	raw, _ := json.Marshal(r)
	if err := svc.ImportEvidenceSources(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	p, err := svc.prepareReportInput(context.Background(), mustEvent(t, svc, snap.EventID))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, issue := range p.Evaluation.Manifest.Issues {
		found = found || issue.Code == "source_history_coverage_gap"
	}
	if !found {
		t.Fatal("coverage gap not diagnosed")
	}
	for _, f := range p.Evaluation.Result.Findings {
		if f.FactID == "F_DST_NOVELTY" && f.Status != evidence.Missing {
			t.Fatal("incomplete history became negative/novelty claim")
		}
	}
}

type noEvidenceWrites struct {
	store.Store
	writes int
}

func (s *noEvidenceWrites) PutAggregateRecord(context.Context, store.AggregateRecord) error {
	s.writes++
	return errors.New("validation attempted write")
}

func TestRealValidationUsesReportPipelineWithoutAnyWrites(t *testing.T) {
	svc, snap, r := sourceFixture(t)
	raw, _ := json.Marshal(r)
	if err := svc.ImportEvidenceSources(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	guard := &noEvidenceWrites{Store: svc.Store}
	svc.Store = guard
	validation, err := svc.ValidateReportEvidence(context.Background(), snap.EventID)
	if err != nil || guard.writes != 0 || validation.Evaluation.Status != "evaluated" || len(validation.Evaluation.Manifest.FactCoverage) != 59 || validation.Reads["hit_page"].Calls != 2 || validation.Reads["record:evidence_sources"].Calls != 1 || validation.Evaluation.Result != nil {
		t.Fatalf("unsafe/incomplete validation: %v %+v writes=%d", err, validation, guard.writes)
	}
}

func TestSourceReadFailureDoesNotCacheAndDoesNotLeakDriverErrors(t *testing.T) {
	svc, snap, _ := sourceFixture(t)
	fault := &evidenceFaultStore{Store: svc.Store, failKind: "evidence_sources"}
	svc.Store = fault
	raw, err := svc.PrepareReportEvidence(context.Background(), mustEvent(t, svc, snap.EventID))
	if err != nil || strings.Contains(raw, "SECRET") {
		t.Fatalf("unsafe failure: %v", err)
	}
	cache, _ := svc.Store.AggregateRecords(context.Background(), "evidence_result", snap.EventID, 10)
	if len(cache) != 0 {
		t.Fatal("transient source failure cached")
	}
	d, err := svc.EvidenceInputDiagnostics(context.Background(), snap.EventID, snap.Version)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, i := range d.Manifest.Issues {
		found = found || i.Code == "source_registry_read_failed" && i.Retryable
	}
	if !found {
		t.Fatal("source query failure hidden")
	}
}

func TestAllReportKindsActuallySendProducedSourceFacts(t *testing.T) {
	for _, kind := range []string{AnalysisKindInitial, AnalysisKindFinal, AnalysisKindManual} {
		t.Run(kind, func(t *testing.T) {
			svc, snap, r := sourceFixture(t)
			raw, _ := json.Marshal(r)
			if err := svc.ImportEvidenceSources(context.Background(), raw); err != nil {
				t.Fatal(err)
			}
			prompt := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var body struct {
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				if json.NewDecoder(req.Body).Decode(&body) != nil {
					t.Error("bad model request")
					return
				}
				for _, m := range body.Messages {
					if m.Role == "user" && m.Content != "health" {
						prompt = m.Content
					}
				}
				w.Header().Set("Content-Type", "application/json")
				reply := "OK"
				if prompt != "" {
					reply = acceptedReportResponse(t, prompt)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": reply}}}})
			}))
			defer server.Close()
			svc.LLM = &client.LLMClient{BaseURL: server.URL, Model: "fixture", HTTP: server.Client()}
			version := 1
			if kind == AnalysisKindFinal {
				version = 2
			}
			if kind == AnalysisKindManual {
				version = 3
			}
			if err := svc.runAnalysis(context.Background(), snap.EventID, kind, version); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(prompt, "F_DST_NOVELTY") || strings.Contains(prompt, "independent-reviewed-history-export") {
				t.Fatal("produced history absent or full registry leaked to model")
			}
			event := mustEvent(t, svc, snap.EventID)
			if event.AnalysisVersion != version {
				t.Fatal("report not saved")
			}
		})
	}
}

type failingEvidenceAssetRegistry struct{ store.Store }

func (s *failingEvidenceAssetRegistry) ListAssetsContext(context.Context) ([]domain.Asset, error) {
	return nil, errors.New("driver SECRET")
}

func TestAssetRegistryFailureIsExplicitAndCannotPoisonCache(t *testing.T) {
	svc, snap, _ := sourceFixture(t)
	ctx := context.Background()
	original := svc.Store
	event := mustEvent(t, svc, snap.EventID)
	svc.Store = &failingEvidenceAssetRegistry{Store: original}
	p, err := svc.prepareReportInput(ctx, event)
	if err != nil || p.Evaluation.Status != "unavailable" || p.Evaluation.Reason != "asset_registry_unavailable" || strings.Contains(p.Context, "SECRET") {
		t.Fatal("registry failure was hidden or broke original report")
	}
	found := false
	for _, i := range p.Evaluation.Manifest.Issues {
		found = found || i.Code == "asset_registry_read_failed" && i.Retryable
	}
	if !found {
		t.Fatal("missing registry query diagnostics")
	}
	cached, _ := original.AggregateRecords(ctx, "evidence_result", snap.EventID, 10)
	if len(cached) != 0 {
		t.Fatal("registry failure poisoned cache")
	}
	svc.Store = original
	p, err = svc.prepareReportInput(ctx, event)
	if err != nil || p.Evaluation.Status != "evaluated" || p.Evaluation.CacheHit {
		t.Fatal("registry recovery did not reevaluate")
	}
}

func TestNormalBaselineRequiresAuditedPastTrainingPopulation(t *testing.T) {
	_, _, r := sourceFixture(t)
	e := &r.Entries[0]
	p := e.Input.History.Provenance
	e.Input.Baselines = []evidence.Baseline{{Provenance: p, FactID: "F_RATE_BURST", Metrics: map[string]float64{"mean_per_5m": 10, "burst_ratio_p99": 4}}}
	e.BaselineTraining = &EvidenceBaselineTraining{Provenance: p, Window: evidence.AnalysisWindow{Start: e.Input.Window.Start.Add(-time.Hour), End: e.Input.Window.Start}, Samples: 30, NormalClassificationSource: "independent-normal-classification", Population: "full_normal_flows"}
	if err := validateEvidenceSources(r); err != nil {
		t.Fatal(err)
	}
	e.BaselineTraining.Population = "alert_only"
	if validateEvidenceSources(r) == nil {
		t.Fatal("attack-only baseline accepted")
	}
	e.BaselineTraining.Population = "full_normal_flows"
	e.BaselineTraining.Window.End = e.Input.Window.Start.Add(time.Second)
	if validateEvidenceSources(r) == nil {
		t.Fatal("future training leaked into current analysis")
	}
}
