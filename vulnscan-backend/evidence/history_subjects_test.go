package evidence

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func subjectTestRequest() Request {
	at := time.Date(2026, 10, 21, 4, 0, 0, 0, time.UTC)
	scope := Scope{AssetID: "a", DeviceID: "d", EndpointID: "tcp://203.0.113.1:80"}
	in := Input{Scope: scope, Window: &AnalysisWindow{Start: at, End: at.Add(time.Minute)}}
	r := Request{EventID: "current", SnapshotVersion: 1, Facts: []FactID{"F_HIST_INFRA_PERSISTENCE"}}
	for i, typ := range []string{"ip", "domain", "url"} {
		id := []string{"ip-hit", "domain-hit", "url-hit"}[i]
		value := []string{"203.0.113.1", "same.test", "http://same.test/path"}[i]
		r.Hits = append(r.Hits, Hit{ID: id, OccurredAt: at, Scope: scope})
		h := &HistoryData{PlatformRecords: true, AsOf: at, LookbackStart: at.AddDate(0, 0, -30), IOC: value, Provenance: Provenance{Verified: true, Version: "saved-summary", SourceIDs: []string{"snapshot"}}}
		if typ != "url" {
			for j, asset := range []string{"a", "b"} {
				rowID := typ + "-past-" + asset
				h.Events = append(h.Events, HistoryEvent{ID: rowID, IOCType: typ, IOC: value, AssetID: asset, Time: at.AddDate(0, 0, -j-1)})
				h.SourceIDs = append(h.SourceIDs, rowID)
			}
		}
		in.PlatformHistorySubjects = append(in.PlatformHistorySubjects, HistorySubject{IOCType: typ, IOCValue: value, CurrentSourceIDs: []string{id}, History: h})
	}
	// A supplied legacy branch must not create a fourth result.
	in.PlatformHistory = in.PlatformHistorySubjects[0].History
	r.Inputs = []Input{in}
	return r
}

func TestHistorySubjectsKeepIOCResultsAndExecutionsSeparate(t *testing.T) {
	r := subjectTestRequest()
	engine, _ := NewEngine(DefaultConfig())
	before, _ := json.Marshal(r.Inputs[0].PlatformHistorySubjects)
	result, err := engine.Evaluate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 3 {
		t.Fatalf("legacy branch duplicated subjects: %+v", result.Findings)
	}
	seen := map[string]bool{}
	for _, f := range result.Findings {
		if f.FactID != "F_HIST_INFRA_PERSISTENCE" {
			continue
		}
		if f.IOCType == "url" {
			if f.Status != Missing || f.ReasonCode != IncompleteNegative {
				t.Fatal(f)
			}
		} else if f.Status != Observed {
			t.Fatal(f)
		}
		if f.Measurements.SampleCount != 1 || f.ObservationKind != "event_occurrence" {
			t.Fatal("mixed current populations", f)
		}
		for _, id := range f.SourceIDs {
			if strings.HasSuffix(id, "-hit") && id != f.IOCType+"-hit" {
				t.Fatal("foreign IOC source", f)
			}
		}
		seen[FindingUnifiedID(f)] = true
	}
	if len(seen) != 3 {
		t.Fatal("normalized identity collision")
	}
	n := Normalize(result.Findings, nil, result.Executions)
	for _, u := range n.Items {
		if u.RuleID == "F_HIST_INFRA_PERSISTENCE" && u.ExecutionStatus != "executed" {
			t.Fatal("execution did not match exact IOC", u)
		}
	}
	after, _ := json.Marshal(r.Inputs[0].PlatformHistorySubjects)
	if string(before) != string(after) {
		t.Fatal("engine mutated source subjects")
	}
	// Permute execution statuses to prove first same-Scope row is not reused.
	result.Executions[0].Status = "skipped"
	n = Normalize(result.Findings, nil, result.Executions)
	for _, u := range n.Items {
		if u.RuleID == "F_HIST_INFRA_PERSISTENCE" && u.IOCType != result.Executions[0].IOCType && u.ExecutionStatus != "executed" {
			t.Fatal("execution status crossed IOC", u)
		}
	}
}

func TestHistorySubjectsRejectAmbiguousOrUnboundInputs(t *testing.T) {
	for _, kind := range []string{"duplicate-subject", "duplicate-source", "foreign-scope", "missing-source", "event-type", "event-value"} {
		t.Run(kind, func(t *testing.T) {
			r := subjectTestRequest()
			in := &r.Inputs[0]
			switch kind {
			case "duplicate-subject":
				in.PlatformHistorySubjects = append(in.PlatformHistorySubjects, in.PlatformHistorySubjects[0])
			case "duplicate-source":
				in.PlatformHistorySubjects[0].CurrentSourceIDs = []string{"ip-hit", "ip-hit"}
			case "foreign-scope":
				r.Hits[0].Scope.DeviceID = "foreign"
			case "missing-source":
				in.PlatformHistorySubjects[0].CurrentSourceIDs = []string{"absent"}
			case "event-type":
				in.PlatformHistorySubjects[0].History.Events[0].IOCType = "domain"
			case "event-value":
				in.PlatformHistorySubjects[0].History.Events[0].IOC = "other"
			}
			engine, _ := NewEngine(DefaultConfig())
			if _, err := engine.Evaluate(context.Background(), r); err == nil {
				t.Fatal("invalid subject accepted")
			}
		})
	}
}

func TestHistorySubjectsLegacyAndEqualValuesDoNotCollapse(t *testing.T) {
	r := subjectTestRequest()
	r.Inputs[0].PlatformHistorySubjects[1].IOCValue = "203.0.113.1"
	r.Inputs[0].PlatformHistorySubjects[1].History.IOC = "203.0.113.1"
	for i := range r.Inputs[0].PlatformHistorySubjects[1].History.Events {
		r.Inputs[0].PlatformHistorySubjects[1].History.Events[i].IOC = "203.0.113.1"
	}
	engine, _ := NewEngine(DefaultConfig())
	result, err := engine.Evaluate(context.Background(), r)
	if err != nil || len(result.Findings) != 3 {
		t.Fatal(err, result)
	}
	r.Inputs[0].PlatformHistorySubjects = nil
	result, err = engine.Evaluate(context.Background(), r)
	if err != nil || len(result.Findings) != 1 || result.Findings[0].IOCType != "" {
		t.Fatal("legacy changed", err, result)
	}
}
