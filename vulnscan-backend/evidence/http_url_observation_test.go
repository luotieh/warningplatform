package evidence

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func urlObservationRequest() Request {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	scope := Scope{AssetID: "asset", DeviceID: "node", EndpointID: "tcp://203.0.113.1:80"}
	r := Request{EventID: "url-subset", SnapshotVersion: 1, Facts: []FactID{"F_URL_ODD_AUTHORITY"}, Quality: Quality{Coverage: CoveragePartial}, Hits: []Hit{{ID: "h1", Scope: scope, OccurredAt: at}, {ID: "h2", Scope: scope, OccurredAt: at.Add(time.Second)}}}
	h := &HTTPData{Provenance: Provenance{Verified: true, Complete: false, Version: "saved:1", SourceIDs: []string{"h1", "h2"}}}
	for _, hit := range r.Hits {
		record := HTTPRecord{SourceID: hit.ID, RequestID: hit.ID + ":request", SessionID: "session", Time: hit.OccurredAt, URL: "http://example.org/path", Method: "GET"}
		record.RequestVerification = &HTTPRequestVerification{Version: HTTPRequestVerificationVersion, Scope: scope, SourceID: hit.ID, SourceOccurredAt: hit.OccurredAt, RequestID: record.RequestID, RequestTime: record.Time, URL: record.URL, Method: record.Method, SessionID: record.SessionID}
		h.Records = append(h.Records, record)
	}
	r.Inputs = []Input{{Scope: scope, Window: &AnalysisWindow{Start: at, End: at.Add(time.Hour)}, HTTP: h}}
	return r
}

func evaluateURLObservation(t *testing.T, r Request) Finding {
	t.Helper()
	e, _ := NewEngine(DefaultConfig())
	result, err := e.Evaluate(context.Background(), r)
	if err != nil || len(result.Findings) != 1 {
		t.Fatal(result, err)
	}
	f := result.Findings[0]
	if f.Eligibility == "eligible" {
		n := Normalize(result.Findings, nil, result.Executions)
		matched := false
		for _, item := range n.Items {
			if item.RuleID == string(f.FactID) && item.Scope == f.Scope && item.ObservationKind == "complete_http_request" && item.ExecutionStatus == "executed" {
				matched = true
			}
		}
		if !matched {
			t.Fatal("typed execution identity lost")
		}
	}
	return f
}

func TestVerifiedHTTPURLObservationSubset(t *testing.T) {
	r := urlObservationRequest()
	f := evaluateURLObservation(t, r)
	if f.Status != NotObserved || f.Measurements.SampleCount != 2 || len(f.SourceIDs) != 2 || r.Inputs[0].HTTP.Complete {
		t.Fatal("limited request negative failed or family completeness changed", f)
	}
	// The verification contract survives the public JSON path without RawRequest.
	b, _ := json.Marshal(r)
	var restored Request
	if err := json.Unmarshal(b, &restored); err != nil {
		t.Fatal(err)
	}
	if got := evaluateURLObservation(t, restored); got.Status != NotObserved || got.Measurements.SampleCount != 2 {
		t.Fatal("serialized verification lost", got)
	}
	r.Inputs[0].HTTP.Records[0].URL = "http://user@203.0.113.1/login"
	r.Inputs[0].HTTP.Records[0].RequestVerification.URL = r.Inputs[0].HTTP.Records[0].URL
	if got := evaluateURLObservation(t, r); got.Status != Observed || got.Measurements.Values["odd_authority_count"] != 1 {
		t.Fatal("actual URL structure not detected", got)
	}
}

func TestVerifiedHTTPURLObservationRejectsAndDeduplicates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*HTTPRecord)
	}{
		{"unverified", func(r *HTTPRecord) { r.RequestVerification = nil }},
		{"truncated", func(r *HTTPRecord) { r.Truncated = true }},
		{"scope", func(r *HTTPRecord) { r.RequestVerification.Scope.DeviceID = "peer" }},
		{"source_time", func(r *HTTPRecord) { r.RequestVerification.SourceOccurredAt = r.Time.Add(time.Hour) }},
		{"url_changed", func(r *HTTPRecord) { r.URL = "http://user@203.0.113.1/" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := urlObservationRequest()
			tc.change(&r.Inputs[0].HTTP.Records[0])
			f := evaluateURLObservation(t, r)
			if f.Status != NotObserved || f.Measurements.SampleCount != 1 || len(f.SourceIDs) != 1 || f.SourceIDs[0] != "h2" {
				t.Fatal("bad request leaked into source subset", f)
			}
		})
	}
	r := urlObservationRequest()
	h := r.Inputs[0].HTTP
	h.Records = append(h.Records, h.Records[0])
	f := evaluateURLObservation(t, r)
	if f.Measurements.SampleCount != 2 || len(f.SourceIDs) != 2 || f.Measurements.Values["duplicate_request_projections"] != 1 {
		t.Fatal("duplicate inflated sample count", f)
	}
	copy := h.Records[0]
	v := *copy.RequestVerification
	copy.RequestVerification = &v
	copy.URL, v.URL = "http://user@203.0.113.1/", "http://user@203.0.113.1/"
	h.Records = append(h.Records, copy)
	f = evaluateURLObservation(t, r)
	if f.Status != NotObserved || f.Measurements.SampleCount != 1 || len(f.SourceIDs) != 1 || f.SourceIDs[0] != "h2" || f.Measurements.Values["conflicting_request_groups"] != 1 {
		t.Fatal("conflicting identity survived", f)
	}
	// Existing complete-family Mock remains supported without the new marker;
	// partial unmarked input remains missing, and other HTTP facts stay gated.
	r = urlObservationRequest()
	for i := range r.Inputs[0].HTTP.Records {
		r.Inputs[0].HTTP.Records[i].RequestVerification = nil
	}
	if got := evaluateURLObservation(t, r); got.Status != Missing {
		t.Fatal(got)
	}
	r.Inputs[0].HTTP.Complete = true
	engine, _ := NewEngine(DefaultConfig())
	legacy, err := engine.Evaluate(context.Background(), r)
	if err != nil || legacy.Findings[0].Status != NotObserved || legacy.Findings[0].ObservationKind != "" {
		t.Fatal("legacy path changed", legacy, err)
	}
	r = urlObservationRequest()
	r.Facts = []FactID{"F_HTTP_FIELD_ENCODING"}
	other, err := engine.Evaluate(context.Background(), r)
	if err != nil || other.Findings[0].Status != Missing || other.Findings[0].ReasonCode != UnverifiedCoverage {
		t.Fatal("unrelated rule complete gate bypassed", other, err)
	}
}
