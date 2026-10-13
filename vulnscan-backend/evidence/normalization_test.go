package evidence

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestUnreviewedHistoryRunsBothSemanticSlotsWithValidatedSources(t *testing.T) {
	for _, index := range []int{21, 22} {
		r := semanticFixture(semanticSpecs[index])
		for k := range r.Subjects[0].Materials {
			m := &r.Subjects[0].Materials[k]
			m.AdjudicationID = ""
			m.AdjudicationSource = ""
			m.FalsePositive = false
		}
		e := semanticTestEngine(t)
		result, err := e.Evaluate(context.Background(), r, semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) { return semanticResponse(call, nil), nil }))
		if err != nil || len(result.Findings) != 1 || result.Plan.Executions[0].Status != "accepted" {
			t.Fatalf("unreviewed history rejected: %v %+v", err, result)
		}
		result, err = e.Evaluate(context.Background(), r, semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) {
			return semanticResponse(call, func(i *SemanticItem) { i.AdjudicationRefs = []string{"invented-history-reference"} }), nil
		}))
		if err != nil || len(result.Findings) != 0 || result.Plan.Executions[0].Reason != "undelivered_or_missing_reference" {
			t.Fatal("invented history reference accepted")
		}
	}
}

func TestNormalizationPreservesAllCatalogStatesAndMeasurements(t *testing.T) {
	r, c := fullFixture(BeaconPeriodic)
	f := boundHistoryFinding(t, r, c)
	f.Parameters.Values = map[string]float64{"threshold": 0.2}
	missing := f
	missing.FactID = MultiDayPersist
	missing.Status = Missing
	missing.ReasonCode = MissingInput
	negative := f
	negative.FactID = "F_BEACON_JITTER"
	negative.Status = NotObserved
	n := Normalize([]Finding{f, missing, negative}, nil, []Execution{{FactID: f.FactID, Scope: f.Scope, Status: "executed"}})
	if len(n.Items) != 82 {
		t.Fatalf("catalog coverage=%d", len(n.Items))
	}
	found := map[string]UnifiedEvidence{}
	for _, u := range n.Items {
		found[u.RuleID] = u
	}
	if found[string(MultiDayPersist)].Role != "gap" || found["F_BEACON_JITTER"].Role != "negative_result" {
		t.Fatal("missing became negative")
	}
	u := found[string(BeaconPeriodic)]
	if u.ExecutionStatus != "executed" || u.Parameters.Values["threshold"] != 0.2 || u.Measurements.SampleCount != f.Measurements.SampleCount || len(u.SourceIDs) != len(f.SourceIDs) {
		t.Fatal("normalization lost actual result")
	}
	other := f
	other.Scope.AssetID = "other-asset"
	n = Normalize([]Finding{f, other}, nil)
	ids := map[string]bool{}
	for _, u := range n.Items {
		if ids[u.ID] {
			t.Fatal("scope identity collision")
		}
		ids[u.ID] = true
	}
	if len(n.Items) != 83 {
		t.Fatal("separate scopes were collapsed")
	}
}

func TestCompressionRetainsHistoryAndCountsWithoutMutatingFullIndex(t *testing.T) {
	n := Normalize(nil, nil)
	n.Items = append(n.Items,
		UnifiedEvidence{ID: "history", ReportID: "E001", Kind: "fact", RuleID: "F_HIST_ASSET_IOC_RECURRENCE", Status: "observed", Role: "measured_fact", SourceIDs: []string{"old-1", "old-2"}},
		UnifiedEvidence{ID: "interpretation", ReportID: "E002", Kind: "semantic", RuleID: "R06/history.activity_association/", Status: "accepted", Role: "context_interpretation"},
		UnifiedEvidence{ID: "duplicate", ReportID: "E003", Kind: "semantic", Status: "accepted", Role: "duplicate", DuplicateOf: "interpretation"},
		UnifiedEvidence{ID: "oversize", ReportID: "E004", Kind: "observation", Role: "observation", Interpretation: strings.Repeat("x", 5000)},
	)
	n.Recount()
	before, _ := json.Marshal(n)
	d := Compress(n, CompressionOptions{MaxItems: 2, MaxRunes: 2000})
	if len(d.SelectedIDs) != 2 || d.SelectedIDs[0] != "E001" || d.SelectedIDs[1] != "E002" || d.TotalInstances != 86 || d.Omitted != 84 || d.Counts["semantic:accepted"] != 2 || d.GapReasons["no_execution_result"] != 82 {
		t.Fatalf("digest=%+v", d)
	}
	after, _ := json.Marshal(n)
	if string(before) != string(after) {
		t.Fatal("compression changed full index")
	}
	d = Compress(n, CompressionOptions{MaxItems: 12, MaxRunes: 1})
	if len(d.SelectedIDs) != 0 || d.Omitted != 86 {
		t.Fatal("budget sliced a record")
	}
}

func TestPlatformPartialHistoryCanProveRecurrenceButCannotRefute(t *testing.T) {
	for _, count := range []int{2, 1} {
		r, c := fullFixture("F_HIST_ASSET_IOC_RECURRENCE")
		h := r.Inputs[0].History
		h.Complete = false
		h.PlatformRecords = true
		h.Events = h.Events[:count]
		for i := range h.Events {
			h.Events[i].Adjudication = ""
			h.Events[i].AdjudicationID = ""
			h.Events[i].AdjudicationSource = ""
		}
		f := boundHistoryFinding(t, r, c)
		if count == 2 && (f.Status != Observed || f.Quality != "partial") {
			t.Fatalf("positive partial history lost: %+v", f)
		}
		if count == 1 && (f.Status != Missing || f.ReasonCode != IncompleteNegative || f.Measurements.Values["independent_events"] != 1) {
			t.Fatalf("partial history refuted recurrence: %+v", f)
		}
	}
}
