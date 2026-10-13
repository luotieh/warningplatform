package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type historyCountingStore struct {
	store.Store
	Calls int
	Fail  bool
}

func TestPlatformHistoryBudgetAndNormalizedDelivery(t *testing.T) {
	svc, event, _ := reportTestBundle(t)
	snap, err := svc.EvidenceSnapshot(context.Background(), event.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	at, _ := time.Parse(time.RFC3339Nano, asString(snap.Context["first_time"]))
	prior := at.Add(-24 * time.Hour)
	event.Observables = []domain.IOC{{Type: "ip", Value: "192.0.2.2"}}
	for n := 0; n < 202; n++ {
		addHistoryFixture(t, svc.Store, fmt.Sprintf("prior-%03d", n), "192.0.2.1", "192.0.2.2", prior, "rejected")
	}
	h := svc.loadReportHistory(context.Background(), event, snap, svc.Store.ListAssets())
	if !h.Truncated || h.Status != "partial" || len(h.Rows) != 200 {
		t.Fatalf("bounded history: %+v", h)
	}
	p, err := svc.prepareReportInputMode(context.Background(), event, false)
	if err != nil {
		t.Fatal(err)
	}
	bundle := p.Evidence
	prompt, err := evidenceReportPrompt(event, p, bundle, "")
	if err != nil || strings.Contains(prompt, "history_background") || !strings.Contains(prompt, "evidence_digest") {
		t.Fatal("normalization not delivered", err)
	}
	doc := ReportDocument{SchemaVersion: reportEvidenceVersion, EventID: event.EventID, Evidence: bundle, Assessment: validReportAssessment(bundle)}
	doc.Markdown = renderReportMarkdown(doc)
	if _, err := ExportEvidenceReportDOCX(doc); err != nil {
		t.Fatal("history export failed", err)
	}
}

func (s *historyCountingStore) HistoryCandidates(ctx context.Context, q store.HistoryQuery) ([]domain.Event, error) {
	s.Calls++
	if s.Fail {
		return nil, errors.New("query fixture failure")
	}
	return s.Store.HistoryCandidates(ctx, q)
}
func addHistoryFixture(t *testing.T, st store.Store, id, src, dst string, at time.Time, status string) {
	t.Helper()
	c, _ := json.Marshal(map[string]any{"src_ip": src, "dst_ip": dst, "first_time": at.Format(time.RFC3339Nano), "last_time": at.Format(time.RFC3339Nano), "ioc": map[string]any{"ioc_value": dst, "ioc_type": "ip"}, "ai_probability": 99})
	_, err := st.CreateEvent(domain.Event{EventID: id, Context: string(c), CreatedAt: at, LastSeenAt: &at, ReviewStatus: status, ReviewedBy: "client-supplied-reviewer", ReviewedAt: &at, ReviewComment: "模型认为恶意"})
	if err != nil {
		t.Fatal(err)
	}
}
func TestPlatformHistoryMatchesAndNeverInfersAdjudication(t *testing.T) {
	svc, event, _ := reportTestBundle(t)
	snap, err := svc.EvidenceSnapshot(context.Background(), event.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	at, _ := time.Parse(time.RFC3339Nano, asString(snap.Context["first_time"]))
	event.Observables = []domain.IOC{{Type: "ip", Value: "192.0.2.2"}}
	addHistoryFixture(t, svc.Store, "same-both", "192.0.2.1", "192.0.2.2", at.Add(-48*time.Hour), "approved")
	addHistoryFixture(t, svc.Store, "same-ioc", "192.0.2.9", "192.0.2.2", at.Add(-24*time.Hour), "rejected")
	addHistoryFixture(t, svc.Store, "same-asset", "192.0.2.1", "192.0.2.8", at.Add(-24*time.Hour), "pending")
	addHistoryFixture(t, svc.Store, "future", "192.0.2.1", "192.0.2.2", at, "approved")
	addHistoryFixture(t, svc.Store, "expired", "192.0.2.1", "192.0.2.2", at.AddDate(0, 0, -31), "approved")
	addHistoryFixture(t, svc.Store, "unrelated", "192.0.2.9", "192.0.2.8", at.Add(-24*time.Hour), "approved")
	h := svc.loadReportHistory(context.Background(), event, snap, svc.Store.ListAssets())
	if h.Status != "available" || len(h.Rows) != 3 {
		t.Fatalf("history=%+v", h)
	}
	relations := map[string]string{}
	for _, row := range h.Rows {
		relations[row.EventID] = row.Relation
		if row.Adjudication != "unreviewed" {
			t.Fatal("workflow approval/rejection became an adjudication")
		}
	}
	if relations["same-both"] != "same_asset_ioc" || relations["same-ioc"] != "same_ioc" || relations["same-asset"] != "same_asset" {
		t.Fatal(relations)
	}
	bundle := buildReportEvidence(event, snap, SnapshotFactEvaluation{Status: "evaluated", Manifest: SnapshotEvidenceManifest{LoadedHits: snap.Count}}, ReportSemanticEvaluation{}, h)
	for _, entry := range bundle.Entries {
		if entry.Kind == "history_background" {
			t.Fatal("history bypassed evidence engine")
		}
	}

}
func TestHistoryQueryFailureDoesNotPoisonFactCacheAndReadsOnce(t *testing.T) {
	svc, event, _ := reportTestBundle(t)
	count := &historyCountingStore{Store: svc.Store, Fail: true}
	svc.Store = count
	p, err := svc.prepareReportInputMode(context.Background(), event, true)
	if err != nil || p.Evaluation.Status != "evaluated" || p.Evidence.History == nil || p.Evidence.History.Reason != "history_query_failed" || count.Calls != 1 {
		t.Fatalf("degradation: err=%v history=%+v calls=%d", err, p.Evidence.History, count.Calls)
	}
	count.Fail = false
	p, err = svc.prepareReportInputMode(context.Background(), event, true)
	if err != nil || p.Evaluation.CacheHit || p.Evidence.History.Status != "available" || count.Calls != 2 {
		t.Fatalf("recovery: %v cache=%v calls=%d", err, p.Evaluation.CacheHit, count.Calls)
	}
}

func TestHistoryActuallyFeedsAlgorithmsAndBothSemanticSlots(t *testing.T) {
	svc, event, _ := reportTestBundle(t)
	snap, err := svc.EvidenceSnapshot(context.Background(), event.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	at, _ := time.Parse(time.RFC3339Nano, asString(snap.Context["first_time"]))
	event.Observables = []domain.IOC{{Type: "ip", Value: "192.0.2.2"}}
	addHistoryFixture(t, svc.Store, "previous-approved", "192.0.2.1", "192.0.2.2", at.Add(-48*time.Hour), "approved")
	addHistoryFixture(t, svc.Store, "previous-rejected", "192.0.2.1", "192.0.2.2", at.Add(-24*time.Hour), "rejected")
	p, err := svc.prepareReportInputMode(context.Background(), event, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range p.Evaluation.Result.Findings {
		if f.FactID == "F_HIST_ASSET_IOC_RECURRENCE" && f.Status == evidence.Observed && f.Measurements.Values["independent_events"] == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("history never reached recurrence rule: %+v", p.Evaluation.Result.Findings)
	}
	opts := DefaultSnapshotEvidenceOptions()
	opts.Facts = evidence.SupportedFacts()
	opts.CaptureSemantic = true
	opts.PlatformHistory = p.Evidence.History
	input, err := svc.SnapshotEvidenceInput(context.Background(), snap, svc.Store.ListAssets(), opts)
	if err != nil {
		t.Fatal(err)
	}
	request := buildSnapshotSemanticRequest(snap, input, p.Evaluation.Result, evidence.SemanticRaw)
	request.Slots = []evidence.SlotKey{}
	for _, d := range evidence.SemanticDefinitions() {
		if d.Key.ID == "R06" || d.Key.ID == "R07" {
			request.Slots = append(request.Slots, d.Key)
		}
	}
	engine, _ := evidence.NewSemanticEngine(evidence.DefaultSemanticConfig())
	plan, err := engine.Plan(context.Background(), request)
	if err != nil || len(plan.Tasks) != 2 {
		t.Fatalf("history slots: %v %+v", err, plan.Executions)
	}
	for _, task := range plan.Tasks {
		refs := []string{}
		for _, m := range task.Materials {
			refs = append(refs, m.SourceIDs...)
		}
		if !strings.Contains(strings.Join(refs, ","), "previous-approved") || !strings.Contains(strings.Join(refs, ","), "previous-rejected") {
			t.Fatal("review state filtered semantic history", refs)
		}
	}
	prompt, err := evidenceReportPrompt(event, p, p.Evidence, "")
	if err != nil || !strings.Contains(prompt, "F_HIST_ASSET_IOC_RECURRENCE") || !strings.Contains(prompt, "normalized_id") {
		t.Fatal("fact digest missing", err)
	}
}
