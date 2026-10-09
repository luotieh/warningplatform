package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// All identities and hits in these fixtures are synthetic, not replay acceptance data.
func testRequest() Request {
	packets, truncated := uint64(1), false
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r := Request{EventID: "synthetic-event", SnapshotVersion: 1,
		Quality: Quality{Coverage: CoverageComplete, CaptureTruncated: &truncated}}
	for i := 0; i < 8; i++ {
		r.Hits = append(r.Hits, Hit{ID: string(rune('a' + i)), OccurredAt: start.Add(time.Duration(i) * time.Minute), Packets: &packets,
			Scope: Scope{AssetID: "synthetic-asset", EndpointID: "synthetic-endpoint", DeviceID: "synthetic-device"}})
	}
	return r
}

func evaluate(t *testing.T, e *Engine, r Request) Result {
	t.Helper()
	result, err := e.Evaluate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPeriodicAndTrace(t *testing.T) {
	e := testEngine(t)
	r := testRequest()
	out := evaluate(t, e, r)
	f := out.Findings[0]
	if f.Status != Observed || f.Eligibility != "eligible" || f.Measurements.IntervalCV == nil || *f.Measurements.IntervalCV != 0 || *f.Measurements.MedianIntervalSeconds != 60 {
		t.Fatalf("unexpected periodic finding: %+v", f)
	}
	if f.SnapshotVersion != r.SnapshotVersion || len(f.SourceIDs) != 8 || f.Window.Convention != "observed_first_last_inclusive" || f.RuleVersion != RuleVersion {
		t.Fatalf("missing provenance: %+v", f)
	}
	if out.Findings[1].Status != NotObserved {
		t.Fatal("expected one observed day")
	}
	if _, err := json.Marshal(out); err != nil {
		t.Fatal(err)
	}
}

func TestPeriodicPreconditions(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(*Request)
		reason ReasonCode
	}{
		{"small_sample", func(r *Request) { r.Hits = r.Hits[:7] }, InsufficientSamples},
		{"missing_packets", func(r *Request) { r.Hits[0].Packets = nil }, MissingPackets},
		{"unknown_coverage", func(r *Request) { r.Quality = Quality{} }, UnverifiedCoverage},
		{"unknown_truncation", func(r *Request) { r.Quality.CaptureTruncated = nil }, UnverifiedCoverage},
		{"truncated", func(r *Request) { value := true; r.Quality.CaptureTruncated = &value }, UnverifiedCoverage},
		{"missing_time", func(r *Request) { r.Hits[0].OccurredAt = time.Time{} }, InvalidTime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := testRequest()
			tc.edit(&r)
			out := evaluate(t, testEngine(t), r)
			f := out.Findings[0]
			if f.Status != Missing || f.Eligibility != "ineligible" || f.ReasonCode != tc.reason || out.Executions[0].Status != "skipped" || f.Measurements.IntervalCV != nil {
				t.Fatalf("precondition did not skip statistics: %+v", out)
			}
		})
	}
}

func TestPeriodicNegativeConditions(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Request)
	}{
		{"excess_packets", func(r *Request) { n := uint64(6); r.Hits[0].Packets = &n }},
		{"short_intervals", func(r *Request) {
			for i := range r.Hits {
				r.Hits[i].OccurredAt = r.Hits[0].OccurredAt.Add(time.Duration(i) * 4 * time.Second)
			}
		}},
		{"long_intervals", func(r *Request) {
			start := r.Hits[0].OccurredAt
			for i := range r.Hits {
				r.Hits[i].OccurredAt = start.Add(time.Duration(i) * 25 * time.Hour)
			}
		}},
		{"irregular", func(r *Request) { r.Hits[7].OccurredAt = r.Hits[6].OccurredAt.Add(2 * time.Minute) }},
		{"same_timestamp", func(r *Request) {
			for i := range r.Hits {
				r.Hits[i].OccurredAt = r.Hits[0].OccurredAt
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := testRequest()
			tc.edit(&r)
			out := evaluate(t, testEngine(t), r)
			if out.Findings[0].Status != NotObserved || out.Executions[0].Status != "executed" {
				t.Fatalf("expected negative: %+v", out)
			}
			if _, err := json.Marshal(out); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPopulationVarianceAndMedian(t *testing.T) {
	r := testRequest()
	r.Hits[7].OccurredAt = r.Hits[6].OccurredAt.Add(2 * time.Minute)
	f := evaluate(t, testEngine(t), r).Findings[0]
	// Six intervals of 60 and one of 120: population CV = sqrt(6)/8.
	if math.Abs(*f.Measurements.IntervalCV-math.Sqrt(6)/8) > 1e-12 || *f.Measurements.MedianIntervalSeconds != 60 {
		t.Fatalf("incorrect measurements: %+v", f.Measurements)
	}
}

func TestInclusiveIntervalAndPacketBoundaries(t *testing.T) {
	for _, step := range []time.Duration{5 * time.Second, 24 * time.Hour} {
		r := testRequest()
		start := r.Hits[0].OccurredAt
		n := uint64(5)
		for i := range r.Hits {
			r.Hits[i].OccurredAt = start.Add(time.Duration(i) * step)
			r.Hits[i].Packets = &n
		}
		if evaluate(t, testEngine(t), r).Findings[0].Status != Observed {
			t.Fatalf("boundary rejected: %v", step)
		}
	}
}

func TestBeijingDayBoundaryAndIncompleteCoverage(t *testing.T) {
	e := testEngine(t)
	r := testRequest()
	r.Facts = []FactID{MultiDayPersist}
	// Both observations are Oct 1 UTC, but they cross Beijing midnight.
	r.Hits = r.Hits[:2]
	r.Hits[0].OccurredAt = time.Date(2026, 10, 1, 15, 59, 0, 0, time.UTC)
	r.Hits[1].OccurredAt = time.Date(2026, 10, 1, 16, 1, 0, 0, time.UTC)
	r.Quality = Quality{Coverage: CoveragePartial}
	f := evaluate(t, e, r).Findings[0]
	if f.Status != Observed || *f.Measurements.DaysActive != 2 || f.Quality != "coverage_gap" {
		t.Fatalf("unexpected day result: %+v", f)
	}
	r.Hits = r.Hits[:1]
	out := evaluate(t, e, r)
	f = out.Findings[0]
	if f.Status != Missing || f.ReasonCode != IncompleteNegative || out.Executions[1].Status != "executed" {
		t.Fatalf("partial coverage produced negative: %+v", out)
	}
}

func TestScopeIsolationAndStableOrdering(t *testing.T) {
	r := testRequest()
	for i := 4; i < 8; i++ {
		r.Hits[i].Scope.AssetID = "another-synthetic-asset"
	}
	e := testEngine(t)
	out := evaluate(t, e, r)
	if len(out.Findings) != 4 {
		t.Fatal("scopes merged")
	}
	for _, f := range out.Findings {
		if f.FactID == BeaconPeriodic && f.ReasonCode != InsufficientSamples {
			t.Fatal("different assets were combined")
		}
	}
	for i, j := 0, len(r.Hits)-1; i < j; i, j = i+1, j-1 {
		r.Hits[i], r.Hits[j] = r.Hits[j], r.Hits[i]
	}
	if !reflect.DeepEqual(out, evaluate(t, e, r)) {
		t.Fatal("input order changed evidence")
	}
}

func TestSelectionDoesNotRunOtherAlgorithm(t *testing.T) {
	e := testEngine(t)
	r := testRequest()
	r.Facts = []FactID{MultiDayPersist}
	for i := range r.Hits {
		r.Hits[i].Packets = nil
	}
	out := evaluate(t, e, r)
	if len(out.Findings) != 1 || out.Findings[0].FactID != MultiDayPersist || out.Executions[0].ReasonCode != NotRequested {
		t.Fatalf("selection ignored: %+v", out)
	}
	r.Facts = []FactID{}
	out = evaluate(t, e, r)
	if len(out.Findings) != 0 || len(out.Executions) != 2 {
		t.Fatal("empty selection ran algorithms")
	}
}

func TestPreflightDoesNotPrepareTimes(t *testing.T) {
	e := testEngine(t)
	r := testRequest()
	g := &observations{scope: r.Hits[0].Scope, hits: r.Hits, complete: false}
	e.periodic(g)
	if g.prepared {
		t.Fatal("time processing ran without complete coverage")
	}
	g.complete = true
	g.hits = g.hits[:7]
	e.periodic(g)
	if g.prepared {
		t.Fatal("time processing ran without enough samples")
	}
	g.hits = r.Hits
	g.hits[0].Packets = nil
	e.periodic(g)
	if g.prepared {
		t.Fatal("time processing ran without packets")
	}
}

func TestRejectsInvalidInputAndSelection(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Request)
	}{
		{"duplicate_hit", func(r *Request) { r.Hits[1].ID = r.Hits[0].ID }},
		{"empty_identity", func(r *Request) { r.Hits[0].Scope.AssetID = " " }},
		{"empty_hit", func(r *Request) { r.Hits[0].ID = "" }},
		{"unknown_fact", func(r *Request) { r.Facts = []FactID{"F_UNIMPLEMENTED"} }},
		{"duplicate_fact", func(r *Request) { r.Facts = []FactID{BeaconPeriodic, BeaconPeriodic} }},
		{"empty_event", func(r *Request) { r.EventID = "" }},
		{"no_hits", func(r *Request) { r.Hits = nil }},
		{"invalid_snapshot", func(r *Request) { r.SnapshotVersion = 0 }},
		{"invalid_quality", func(r *Request) { r.Quality.Coverage = "made_up" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := testRequest()
			tc.edit(&r)
			if _, err := testEngine(t).Evaluate(context.Background(), r); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestConfigurationValidationAndSnapshot(t *testing.T) {
	c := DefaultConfig()
	c.Periodic.MaxIntervalCV = math.NaN()
	if _, err := NewEngine(c); err == nil {
		t.Fatal("NaN accepted")
	}
	c = DefaultConfig()
	c.MultiDay.Timezone = "UTC"
	if _, err := NewEngine(c); err == nil {
		t.Fatal("unsupported day timezone accepted")
	}
	c = DefaultConfig()
	e, err := NewEngine(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Periodic.MinSamples = 100
	f := evaluate(t, e, testRequest()).Findings[0]
	if f.Status != Observed || f.Parameters.Periodic.MinSamples != 8 {
		t.Fatal("engine configuration was mutated by caller")
	}
	f.Parameters.Periodic.MinSamples = 100
	if evaluate(t, e, testRequest()).Findings[0].Status != Observed {
		t.Fatal("result mutated engine")
	}
}

func TestCancelledRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := testEngine(t).Evaluate(ctx, testRequest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation: %v", err)
	}
}

func TestConcurrentEngineAndInputImmutability(t *testing.T) {
	e := testEngine(t)
	r := testRequest()
	before, _ := json.Marshal(r)
	expected := evaluate(t, e, r)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := e.Evaluate(context.Background(), r)
			if err != nil || !reflect.DeepEqual(out, expected) {
				t.Errorf("concurrent evaluation differs: %v", err)
			}
		}()
	}
	wg.Wait()
	after, _ := json.Marshal(r)
	if string(before) != string(after) {
		t.Fatal("caller input mutated")
	}
}
