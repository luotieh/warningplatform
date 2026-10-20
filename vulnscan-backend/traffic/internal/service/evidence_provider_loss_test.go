package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestProviderLossGroupObservationsAndAssetInputs(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "a", "192.0.2.10", "d1", at)
	providerTestEvent(t, s, "peer", "b", "192.0.2.11", "d2", at)
	b, a, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Inputs.Request.AssetInputs) != 2 || len(b.Inputs.Request.Groups) != 1 {
		t.Fatal("missing aggregation")
	}
	g := b.Inputs.Request.Groups[0]
	if len(g.Connections) != 2 || g.Complete {
		t.Fatal("group observations lost or completeness invented", g)
	}
	for _, in := range b.Inputs.Request.AssetInputs {
		if in.Scope.EndpointID != "asset://"+in.Scope.AssetID || len(in.Network.Connections) != 1 || in.Network.Complete {
			t.Fatal("asset/device scope or coverage lost")
		}
	}
	if len(b.Inputs.Manifest.PhaseOne.Records) != 2 || len(b.Inputs.Manifest.PhaseOne.Bindings) != 2 {
		t.Fatal("peer manifest dropped")
	}
	stages := map[string]bool{}
	for _, x := range a.Trace {
		stages[x.Stage] = true
	}
	if !stages["S1"] || !stages["S2"] || !stages["S3"] {
		t.Fatal("trace stages missing")
	}
	for _, p := range a.CoverageProofs {
		if p.CollectionCoverage || p.TransactionCoverage || p.Complete {
			t.Fatal("proof upgraded")
		}
	}
	result, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range ProviderExecutionTrace(b, result) {
		stages[x.Stage] = true
	}
	if !stages["S4"] || !stages["S5"] {
		t.Fatal("execution trace missing")
	}
}

func TestProviderLossGroupRejectsForeignDuplicateAndCrossEndpoint(t *testing.T) {
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	scope := evidence.Scope{AssetID: "a", DeviceID: "d", EndpointID: "tcp://198.51.100.20:80"}
	c := evidence.Connection{SourceID: "h", AssetID: "a", Transport: "tcp", Destination: "198.51.100.20", Port: 80, Time: at}
	for _, kind := range []string{"valid", "foreign-source", "wrong-asset", "wrong-time", "duplicate", "wrong-port", "wrong-protocol", "foreign-dns"} {
		t.Run(kind, func(t *testing.T) {
			con := c
			n := &evidence.NetworkData{Connections: []evidence.Connection{con}}
			in := evidence.Input{Scope: scope, Network: n}
			switch kind {
			case "foreign-source":
				con.SourceID = "missing"
				n.Connections = []evidence.Connection{con}
			case "wrong-asset":
				n.Connections[0].AssetID = "b"
			case "wrong-time":
				n.Connections[0].Time = at.Add(time.Second)
			case "duplicate":
				n.Connections = append(n.Connections, con)
			case "wrong-port":
				n.Connections[0].Port = 443
			case "wrong-protocol":
				n.Connections[0].Transport = "udp"
			case "foreign-dns":
				in.DNS = &evidence.DNSData{Records: []evidence.DNSRecord{{SourceID: "h", Time: at.Add(time.Second), Domain: "example.test"}}}
			}
			g := evidence.GroupInput{Endpoint: scope.EndpointID, Window: evidence.AnalysisWindow{Start: at, End: at.Add(time.Minute)}, DNSOwnership: map[string]string{}}
			members := map[string]evidence.Scope{"h": scope}
			if kind == "foreign-source" {
				members["missing"] = scope
			}
			err := populateProviderGroup(&g, evidence.Request{Inputs: []evidence.Input{in}, Hits: []evidence.Hit{{ID: "h", Scope: scope, OccurredAt: at}}}, members)
			if (err == nil) != (kind == "valid") {
				t.Fatal(kind, err)
			}
		})
	}
}

func TestProviderLossDNSOwnershipAndProtocolPartition(t *testing.T) {
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	req := evidence.Request{}
	members := map[string]evidence.Scope{}
	for _, x := range []struct{ asset, device, id string }{{"a", "d1", "current-hit"}, {"b", "d2", "peer-hit"}} {
		scope := evidence.Scope{AssetID: x.asset, DeviceID: x.device, EndpointID: "udp://198.51.100.20:53"}
		members[x.id] = scope
		req.Hits = append(req.Hits, evidence.Hit{ID: x.id, Scope: scope, OccurredAt: at})
		req.Inputs = append(req.Inputs, evidence.Input{Scope: scope, DNS: &evidence.DNSData{Records: []evidence.DNSRecord{{SourceID: x.id, Time: at, Domain: "example.test"}}}, Network: &evidence.NetworkData{Connections: []evidence.Connection{{SourceID: x.id, Time: at, AssetID: x.asset, Transport: "udp", Destination: "198.51.100.20", Port: 53}}}})
	}
	g := evidence.GroupInput{Endpoint: "udp://198.51.100.20:53", Window: evidence.AnalysisWindow{Start: at, End: at.Add(time.Minute)}, DNSOwnership: map[string]string{}}
	if err := populateProviderGroup(&g, req, members); err != nil {
		t.Fatal(err)
	}
	if len(g.DNS) != 2 || g.DNSOwnership["current-hit"] != "a" || g.DNSOwnership["peer-hit"] != "b" {
		t.Fatal("DNS borrowed across assets")
	}
	if len(g.Connections) != 2 || g.Connections[0].Transport != "udp" {
		t.Fatal("protocol partition lost")
	}
}

func TestProviderLossAssetAggregationSeparatesDevicesAndKeepsTransport(t *testing.T) {
	at := time.Now().UTC()
	w := &evidence.AnalysisWindow{Start: at, End: at.Add(time.Minute)}
	r := evidence.Request{Quality: evidence.Quality{Coverage: evidence.CoveragePartial}}
	for i, d := range []string{"one", "two"} {
		proto := []string{"tcp", "udp"}[i]
		r.Inputs = append(r.Inputs, evidence.Input{Scope: evidence.Scope{AssetID: "same-asset", DeviceID: d, EndpointID: proto + "://198.51.100.20:80"}, Window: w, Network: &evidence.NetworkData{Provenance: evidence.Provenance{Verified: true, Complete: false, Version: "v", SourceIDs: []string{d}}, Connections: []evidence.Connection{{SourceID: d, Transport: proto, AssetID: "same-asset"}}}})
	}
	buildProviderAssetInputs(&r)
	if len(r.AssetInputs) != 2 {
		t.Fatal("devices merged")
	}
	for _, in := range r.AssetInputs {
		if len(in.Network.Connections) != 1 || in.Network.Connections[0].SourceID != in.Scope.DeviceID || in.Network.Complete {
			t.Fatal("asset source loss or fabricated coverage")
		}
	}
}

func TestProviderLossHistoryAllBlockersAndURLHostRecovery(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "a", "192.0.2.10", "d1", at)
	before := at.Add(-24 * time.Hour)
	m := map[string]any{"device_id": "d1", "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "first_time": before.Format(time.RFC3339), "last_time": before.Format(time.RFC3339), "ioc": map[string]any{"ioc_type": "domain", "ioc_value": "fixture.test"}, "app": map[string]any{"http_url": "http://fixture.test/path"}}
	raw, _ := json.Marshal(m)
	_, _ = s.CreateEvent(domain.Event{EventID: "history", Context: string(raw), CreatedAt: before, LastSeenAt: &before})
	h := ReportHistory{Start: before.Add(-time.Hour), End: at, MatchAddresses: []string{"192.0.2.10"}, MatchIOCs: []domain.IOC{{Type: "domain", Value: "fixture.test"}}}
	assets := []domain.Asset{{ID: "a", Address: "192.0.2.10", Status: 1}}
	e, _ := s.GetEvent("history")
	out := assembleProviderHistory(h, []domain.Event{e}, assets, map[string]bool{"d1": true}, false)
	if len(out.Rows) != 1 {
		t.Fatal("saved absolute URL host still lost")
	}
	sources := map[string]CollectedSnapshotReference{"history": {EventID: "history", Reason: "published_segment_missing"}}
	checks, err := providerHistoryChecks(out, []domain.Event{e}, assets, map[string]bool{"d1": true}, sources)
	if err != nil || !checks[0].Accepted || !strings.HasPrefix(checks[0].SourceSnapshot, "unavailable:") {
		t.Fatal("snapshot availability falsely claimed", checks, err)
	}
	// Three independently detected faults must not collapse to the first one.
	m["src_ip"] = ""
	m["device_id"] = "foreign"
	m["app"] = map[string]any{}
	raw, _ = json.Marshal(m)
	e.Context = string(raw)
	out = assembleProviderHistory(h, []domain.Event{e}, assets, map[string]bool{"d1": true}, false)
	checks, err = providerHistoryChecks(out, []domain.Event{e}, assets, map[string]bool{"d1": true}, sources)
	if err != nil || len(checks[0].Reasons) != 3 || checks[0].Stage != "S2" {
		t.Fatal("missing independent blockers", checks, err)
	}
}

func TestProviderLossAuditRedactionAndStableTrace(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "a", "192.0.2.10", "d", at)
	_, a, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	_, repeat, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if digest(a.Trace) != digest(repeat.Trace) {
		t.Fatal("trace not reproducible")
	}
	a.Fields = append(a.Fields, EvidenceFieldSupply{Values: []any{"private-password"}})
	raw, _ := json.Marshal(ProviderRedactedAudit(a))
	if strings.Contains(string(raw), "private-password") || strings.Contains(string(raw), "http://fixture.test/path") {
		t.Fatal("raw audit data leaked")
	}
	if len(a.StoredHits) == 0 {
		t.Fatal("redaction mutated internal source ledger")
	}
	x := a.Trace[0]
	oldID := x.TraceID
	sealProviderTrace(&x, x.SnapshotVersion+1)
	if x.TraceID == oldID {
		t.Fatal("snapshot version absent from trace identity")
	}
}

func TestProviderLossHTTPPreservesSavedIDsWithoutInventingTransactions(t *testing.T) {
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	for _, absolute := range []bool{true, false} {
		u := "http://fixture.test/path"
		if !absolute {
			u = "/path"
		}
		raw, _ := json.Marshal(map[string]any{"device_id": "d", "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": "80", "protocol": "tcp", "transaction_id": "tx-saved", "session_id": "session-saved", "response_verified": true, "response_status": 302, "capture_truncated": false, "app": map[string]any{"http_url": u, "http_method": "POST", "user_agent": "saved-UA", "response_verified": true, "brand_claim_verified": true, "body": "password=private"}, "raw_packet": map[string]any{"payload_text": "POST /path HTTP/1.1\r\nHost: fixture.test\r\n\r\n"}})
		snap := EvidenceSnapshot{EventID: "current", Version: 1, Count: 1, Sources: []string{"current"}}
		out, _, _, err := assembleProviderTraffic(snap, []domain.Asset{{ID: "a", Address: "192.0.2.10", Status: 1}}, []store.Hit{{ID: "h", EventID: "current", OccurredAt: at, Raw: raw}}, evidence.AnalysisWindow{Start: at, End: at.Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		in := out.Request.Inputs[0]
		if !absolute {
			if in.HTTP != nil {
				t.Fatal("raw packet or relative URL inferred an HTTP transaction")
			}
			continue
		}
		h := in.HTTP.Records[0]
		if h.TransactionID != "tx-saved" || h.SessionID != "session-saved" || h.Method != "POST" || h.UserAgent != "saved-UA" {
			t.Fatal("saved structured metadata lost", h)
		}
		if h.ResponseVerified || h.RedirectVerified || h.BrandClaimVerified || !h.Truncated || h.ResponseStatus != 0 || h.BodyLength != nil || in.HTTP.Complete {
			t.Fatal("untrusted flags promoted to proof", h)
		}
	}
}

type providerTraceFailureReader struct{ store.EvidenceReader }

func (providerTraceFailureReader) SnapshotPage(context.Context, store.HitQuery, int64, int64, int64) ([]store.Hit, error) {
	return nil, errors.New("injected_query_failure")
}
func TestProviderLossQueryFailureAndEmptyPageRemainAuditable(t *testing.T) {
	a := EvidenceSupplyAudit{}
	r := providerTraceReader{EvidenceReader: providerTraceFailureReader{}, audit: &a}
	_, err := r.SnapshotPage(context.Background(), store.HitQuery{}, 0, 0, 0)
	if err == nil || len(a.Trace) != 1 || a.Trace[0].RejectReason != "QUERY_FAILED:injected_query_failure" || a.Trace[0].Stage != "S1" {
		t.Fatal("query error collapsed to missing source", a.Trace)
	}
	r.EvidenceReader = store.NewMemoryStore()
	_, err = r.SnapshotPage(context.Background(), store.HitQuery{Limit: 10}, 0, 2<<20, 1<<20)
	if err != nil || len(a.Trace) != 2 || a.Trace[1].RejectReason != "" {
		t.Fatal("empty successful query misreported", a.Trace, err)
	}
}

func TestProviderLossQueriedFieldOmissionHasS1Trace(t *testing.T) {
	a := EvidenceSupplyAudit{}
	providerTraceSavedFields(&a, store.Hit{ID: "h", Raw: json.RawMessage(`{"transaction_id":"tx-real","app":{"http_url":"https://fixture.test/?a=1&b=2"}}`)}, evidence.AnalysisWindow{})
	find := func(path string) EvidenceProviderTrace {
		for _, x := range a.Trace {
			if x.FieldPath == "saved.raw."+path {
				return x
			}
		}
		t.Fatal("missing field trace")
		return EvidenceProviderTrace{}
	}
	present := find("transaction_id")
	if present.Stage != "S1" || present.Digest != digest([]any{"tx-real"}) || present.RejectReason != "" {
		t.Fatal("query field not observable", present)
	}
	a.Trace = nil
	providerTraceSavedFields(&a, store.Hit{ID: "h", Raw: json.RawMessage(`{"app":{"http_url":"https://fixture.test/?a=1&b=2"}}`)}, evidence.AnalysisWindow{})
	omitted := find("transaction_id")
	if omitted.Stage != "S1" || omitted.Digest == present.Digest || omitted.RejectReason != "SOURCE_ABSENT_AT_QUERY_RESULT" {
		t.Fatal("projection omission indistinguishable from successful query", omitted)
	}
}
