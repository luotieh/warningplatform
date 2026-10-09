package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/dns/dnsmessage"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func protocolFixture(t *testing.T, payload string, full bool) (evidence.Input, store.Hit, map[string]any) {
	t.Helper()
	h := store.Hit{ID: "actual-hit", OccurredAt: time.Now().UTC()}
	i := evidence.Input{Scope: evidence.Scope{AssetID: "asset", EndpointID: "tcp://203.0.113.2:80", DeviceID: "probe"}}
	m := map[string]any{"protocol": "tcp", "session_id": "session", "transaction_id": "tx", "app": map[string]any{}, "raw_packet": map[string]any{"payload_hex": hex.EncodeToString([]byte(payload)), "capture_truncated": !full}}
	adaptSnapshotProtocols(&i, h, m, "203.0.113.2", 80, full)
	return i, h, m
}

func TestWireHTTPInputsAreCompleteAndCredentialsAreRedacted(t *testing.T) {
	body := "password=SECRET&user=alice"
	wire := fmt.Sprintf("POST /login HTTP/1.1\r\nHost: example.test\r\nUser-Agent: actual-agent\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	i, h, m := protocolFixture(t, wire, true)
	manifest := SnapshotEvidenceManifest{}
	enrichSnapshotProtocols(&i, h, m, &manifest)
	if i.HTTP == nil || len(i.HTTP.Records) != 1 {
		t.Fatalf("wire HTTP not extracted: %+v", manifest)
	}
	r := i.HTTP.Records[0]
	if r.Truncated || r.BodyLength == nil || *r.BodyLength != uint64(len(body)) || r.Fields["password"] != "[redacted]" || r.UserAgent != "actual-agent" || !i.Network.Connections[0].ProtocolParsed {
		t.Fatalf("bad parsed record: %+v", r)
	}
	b, _ := json.Marshal(i)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "alice") {
		t.Fatal("secret persisted in algorithm inputs")
	}
	provenance := evidence.Provenance{Verified: true, Complete: true, Version: "test-wire", SourceIDs: []string{h.ID}}
	i.HTTP.Provenance = provenance
	i.Window = &evidence.AnalysisWindow{Start: h.OccurredAt, End: h.OccurredAt.Add(time.Nanosecond)}
	engine, _ := evidence.NewEngine(evidence.DefaultConfig())
	result, err := engine.Evaluate(context.Background(), evidence.Request{EventID: "e", SnapshotVersion: 1, Hits: []evidence.Hit{{ID: h.ID, Scope: i.Scope, OccurredAt: h.OccurredAt}}, Inputs: []evidence.Input{i}, Facts: []evidence.FactID{"F_CRED_POST_STRUCTURE"}})
	if err != nil || result.Findings[0].Status != evidence.Observed {
		t.Fatalf("complete real request didn't feed credential rule: %v %+v", err, result)
	}
}

func TestHTTPIncompleteAndConflictingInputsCannotBecomeComplete(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		full       bool
		app        map[string]any
		missingURL bool
	}{
		{"short body", "POST / HTTP/1.1\r\nHost: x.test\r\nContent-Length: 20\r\n\r\npwd=x", true, nil, false},
		{"truncated", "POST / HTTP/1.1\r\nHost: x.test\r\nContent-Length: 5\r\n\r\npwd=x", false, nil, false},
		{"unknown media", "POST / HTTP/1.1\r\nHost: x.test\r\nContent-Length: 5\r\n\r\npwd=x", true, nil, false},
		{"pipeline", "GET / HTTP/1.1\r\nHost: x.test\r\n\r\nGET /2 HTTP/1.1\r\nHost: x.test\r\n\r\n", true, nil, false},
		{"metadata conflict", "GET / HTTP/1.1\r\nHost: x.test\r\n\r\n", true, map[string]any{"http_host": "other.test", "http_url": "http://other.test/"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, h, m := protocolFixture(t, tc.wire, tc.full)
			if tc.app != nil {
				m["app"] = tc.app
				adaptSnapshotProtocols(&i, h, m, "203.0.113.2", 80, tc.full)
			}
			manifest := SnapshotEvidenceManifest{}
			enrichSnapshotProtocols(&i, h, m, &manifest)
			if manifest.IssueCount == 0 {
				t.Fatal("no diagnostics")
			}
			if tc.missingURL {
				if i.HTTP != nil && len(i.HTTP.Records) > 0 {
					t.Fatal("conflicting URL retained")
				}
				return
			}
			if i.HTTP == nil || !i.HTTP.Records[0].Truncated {
				t.Fatal("partial input became complete")
			}
		})
	}
}

func TestWireDNSDoesNotInventSuccessfulResponse(t *testing.T) {
	for _, response := range []bool{false, true} {
		name, _ := dnsmessage.NewName("example.test.")
		message := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, Response: response, RCode: dnsmessage.RCodeNameError}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		payload, err := message.Pack()
		if err != nil {
			t.Fatal(err)
		}
		i, h, m := protocolFixture(t, string(payload), true)
		m["protocol"] = "udp"
		m["app"] = map[string]any{"dns_query": "example.test"}
		manifest := SnapshotEvidenceManifest{}
		enrichSnapshotProtocols(&i, h, m, &manifest)
		if i.DNS == nil || len(i.DNS.Records) != 1 || i.DNS.Records[0].RCodeKnown != response {
			t.Fatalf("query/response confused: %+v %+v", i.DNS, manifest)
		}
	}
}

func TestHTTPResponseRequiresActualSequencePairing(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	html := "<form action='https://other.test/login'></form>"
	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", len(html), html)
	req := map[string]any{"tcp_seq": 100, "tcp_ack": 500}
	resp := map[string]any{"tcp_seq": 500, "tcp_ack": 100 + len(request), "capture_truncated": false, "payload_hex": hex.EncodeToString([]byte(response))}
	r := evidence.HTTPRecord{URL: "http://example.test/", SessionID: "s", TransactionID: "t"}
	if reason := snapshotHTTPResponse(&r, req, resp, request); reason != "" || !r.ResponseVerified || r.FormAction != "https://other.test/login" || r.RedirectVerified {
		t.Fatalf("bad verified pair: %s %+v", reason, r)
	}
	r.ResponseVerified = false
	resp["tcp_ack"] = 999
	if reason := snapshotHTTPResponse(&r, req, resp, request); reason != "http_pair_sequence_unverified" || r.ResponseVerified {
		t.Fatal("unpaired response promoted")
	}
}

func TestSupplementalInputBridgeRejectsScopeAndProvenanceErrors(t *testing.T) {
	svc, snap, assets := evidenceAdapterFixture(t, 8)
	base, err := svc.SnapshotEvidenceInput(context.Background(), snap, assets, DefaultSnapshotEvidenceOptions())
	if err != nil {
		t.Fatal(err)
	}
	scope := base.Request.Inputs[0].Scope
	window := base.Request.Inputs[0].Window
	proof := evidence.Provenance{Verified: true, Complete: true, Version: "independent-registry-1", SourceIDs: []string{"registry-record"}}
	extra := SnapshotSupplementalInputs{EventID: snap.EventID, SnapshotVersion: snap.Version, Version: "v1", Inputs: []evidence.Input{{Scope: scope, Window: window, Authorizations: &evidence.AuthorizationData{Provenance: proof, Records: []evidence.AuthorizationRecord{{ID: "exercise", AssetID: scope.AssetID, Endpoint: scope.EndpointID, TaskType: "phishing_exercise", Start: window.Start.Add(-time.Hour), End: window.End.Add(time.Hour)}}}}}}
	if err := svc.StoreSnapshotSupplemental(context.Background(), snap, extra); err != nil {
		t.Fatal(err)
	}
	opts := DefaultSnapshotEvidenceOptions()
	opts.Facts = []evidence.FactID{"F_HIST_EXERCISE"}
	opts.Supplemental = &extra
	result, err := svc.EvaluateSnapshotFacts(context.Background(), snap, assets, opts, evidence.DefaultConfig())
	if err != nil || result.Result.Findings[0].Status != evidence.Observed {
		t.Fatalf("trusted source not connected: %v %+v", err, result)
	}
	extra.Inputs[0].Authorizations.Verified = false
	result, err = svc.EvaluateSnapshotFacts(context.Background(), snap, assets, opts, evidence.DefaultConfig())
	if err != nil || result.Result.Findings[0].Status != evidence.Missing || result.Manifest.IssueCount == 0 {
		t.Fatal("unverified authorization accepted")
	}
	extra.Inputs[0].Authorizations.Verified = true
	copyWindow := *window
	copyWindow.End = copyWindow.End.Add(time.Hour)
	extra.Inputs[0].Window = &copyWindow
	result, err = svc.EvaluateSnapshotFacts(context.Background(), snap, assets, opts, evidence.DefaultConfig())
	if err != nil || result.Result.Findings[0].Status != evidence.Missing {
		t.Fatal("window mismatch accepted")
	}
	extra.SnapshotVersion++
	if err := svc.StoreSnapshotSupplemental(context.Background(), snap, extra); err == nil {
		t.Fatal("wrong snapshot persisted")
	}
}

func TestSupplementalRecordChangeInvalidatesReportCache(t *testing.T) {
	svc, snap, assets := evidenceAdapterFixture(t, 8)
	ctx := context.Background()
	input, _ := svc.SnapshotEvidenceInput(ctx, snap, assets, DefaultSnapshotEvidenceOptions())
	proof := evidence.Provenance{Verified: true, Complete: true, Version: "source", SourceIDs: []string{"authorization"}}
	extra := SnapshotSupplementalInputs{EventID: snap.EventID, SnapshotVersion: snap.Version, Version: "same-version", Inputs: []evidence.Input{{Scope: input.Request.Inputs[0].Scope, Window: input.Request.Inputs[0].Window, Authorizations: &evidence.AuthorizationData{Provenance: proof}}}}
	if err := svc.StoreSnapshotSupplemental(ctx, snap, extra); err != nil {
		t.Fatal(err)
	}
	ev := mustEvent(t, svc, snap.EventID)
	if _, err := svc.PrepareReportEvidence(ctx, ev); err != nil {
		t.Fatal(err)
	}
	extra.Inputs[0].Authorizations.Version = "changed-source"
	if err := svc.StoreSnapshotSupplemental(ctx, snap, extra); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PrepareReportEvidence(ctx, ev); err != nil {
		t.Fatal(err)
	}
	records, _ := svc.Store.AggregateRecords(ctx, "evidence_result", snap.EventID, 0)
	if len(records) != 2 {
		t.Fatal("content changes reused stale evidence")
	}
	diagnostic, err := svc.EvidenceInputDiagnostics(ctx, snap.EventID, 0)
	if err != nil || !diagnostic.ResultPersisted || len(diagnostic.Manifest.FactCoverage) != 59 {
		t.Fatalf("missing complete audit: %v %+v", err, diagnostic)
	}
	for _, row := range diagnostic.Manifest.FactCoverage {
		if !row.Requested || row.Status == "not_requested" {
			t.Fatal("report didn't check all 59")
		}
	}
}

type evidenceFaultStore struct {
	store.Store
	failKind string
	failHits bool
	reads    int
}

func (s *evidenceFaultStore) HitPage(ctx context.Context, q store.HitQuery) ([]store.Hit, error) {
	s.reads++
	if s.failHits {
		return nil, errors.New("driver detail contains SECRET")
	}
	return s.Store.HitPage(ctx, q)
}
func (s *evidenceFaultStore) AggregateRecord(ctx context.Context, k, id string) (store.AggregateRecord, bool, error) {
	if k == s.failKind {
		return store.AggregateRecord{}, false, errors.New("driver SECRET")
	}
	return s.Store.AggregateRecord(ctx, k, id)
}

func TestInputReadFailureIsDiagnosedWithoutAbortingReportOrCaching(t *testing.T) {
	svc, snap, _ := evidenceAdapterFixture(t, 8)
	faults := &evidenceFaultStore{Store: svc.Store, failHits: true}
	svc.Store = faults
	ctx := context.Background()
	ev := mustEvent(t, svc, snap.EventID)
	raw, err := svc.PrepareReportEvidence(ctx, ev)
	if err != nil || !strings.Contains(raw, "snapshot_read_failed") || strings.Contains(raw, "SECRET") || strings.Contains(raw, `"status":"observed"`) {
		t.Fatalf("unsafe failure projection: %v %s", err, raw)
	}
	diagnostic, err := svc.EvidenceInputDiagnostics(ctx, snap.EventID, snap.Version)
	if err != nil || diagnostic.ResultPersisted || diagnostic.Reason != "snapshot_read_failed" || len(diagnostic.Manifest.FactCoverage) != 59 {
		t.Fatalf("failure not traceable: %v %+v", err, diagnostic)
	}
	faults.failHits = false
	raw, err = svc.PrepareReportEvidence(ctx, ev)
	if err != nil || !strings.Contains(raw, `"status":"observed"`) || strings.Contains(raw, "snapshot_read_failed") {
		t.Fatal("transient failure remained cached")
	}
}

func TestSupplementalQueryFailurePreservesCoreFactsAndRetries(t *testing.T) {
	svc, snap, _ := evidenceAdapterFixture(t, 8)
	faults := &evidenceFaultStore{Store: svc.Store, failKind: "evidence_inputs"}
	svc.Store = faults
	ctx := context.Background()
	ev := mustEvent(t, svc, snap.EventID)
	for attempt := 0; attempt < 2; attempt++ {
		raw, err := svc.PrepareReportEvidence(ctx, ev)
		if err != nil || !strings.Contains(raw, `"status":"observed"`) {
			t.Fatal("optional source destroyed core facts")
		}
	}
	records, _ := svc.Store.AggregateRecords(ctx, "evidence_result", snap.EventID, 0)
	if len(records) != 0 {
		t.Fatal("transient source failure cached as absence")
	}
	diagnostic, _ := svc.EvidenceInputDiagnostics(ctx, snap.EventID, snap.Version)
	found := false
	for _, issue := range diagnostic.Manifest.Issues {
		found = found || issue.Code == "supplemental_read_failed" && issue.Retryable
	}
	if !found {
		t.Fatal("source error silently skipped")
	}
}

func TestInputIssueBudgetAndTypedErrors(t *testing.T) {
	manifest := SnapshotEvidenceManifest{}
	for i := 0; i < 300; i++ {
		manifest.addIssue(SnapshotInputIssue{Code: "missing", HitID: fmt.Sprint(i)})
	}
	if manifest.IssueCount != 300 || len(manifest.Issues) != 128 || manifest.OmittedIssues != 172 {
		t.Fatal("diagnostics unbounded or silently lost")
	}
	svc, snap, assets := evidenceAdapterFixture(t, 8)
	snap.Count++
	input, err := svc.SnapshotEvidenceInput(context.Background(), snap, assets, DefaultSnapshotEvidenceOptions())
	var failure *SnapshotInputError
	if !errors.As(err, &failure) || failure.Code != "snapshot_membership_mismatch" || failure.EventID != snap.EventID || input.Request.Hits != nil {
		t.Fatalf("error not typed or partial input retained: %v %+v", err, input.Manifest)
	}
}

func TestAssetWidePortSequenceDoesNotMixPeriodicEndpoints(t *testing.T) {
	ctx := context.Background()
	svc := Services{Store: store.NewMemoryStore()}
	base := time.Now().UTC().Add(-time.Hour)
	var watermark int64
	for i := 0; i < 8; i++ {
		m := testHit(fmt.Sprint(i), base.Add(time.Duration(i)*time.Minute))
		m["protocol"] = "tcp"
		m["dst_port"] = 80 + i
		m["raw_packet"].(map[string]any)["capture_truncated"] = false
		h, _, why := normalizeHit(m, time.Now())
		if why != "" {
			t.Fatal(why)
		}
		h.EventID = "scan"
		stored, err := svc.Store.InsertHit(ctx, h)
		if err != nil {
			t.Fatal(err)
		}
		watermark = stored.Sequence
	}
	snap := EvidenceSnapshot{EventID: "scan", Version: 1, Sources: []string{"scan"}, Watermark: watermark, Count: 8}
	opts := DefaultSnapshotEvidenceOptions()
	opts.Facts = []evidence.FactID{evidence.BeaconPeriodic, "F_PORT_SEQUENCE"}
	assets := []domain.Asset{{ID: "asset", Address: "192.0.2.1", Status: 1}}
	result, err := svc.EvaluateSnapshotFacts(ctx, snap, assets, opts, evidence.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	portObserved := false
	for _, finding := range result.Result.Findings {
		if finding.FactID == "F_PORT_SEQUENCE" {
			portObserved = finding.Status == evidence.Observed && finding.Scope.EndpointID == "asset://asset"
		}
		if finding.FactID == evidence.BeaconPeriodic && finding.Status == evidence.Observed {
			t.Fatal("unrelated endpoints manufactured periodicity")
		}
	}
	if !portObserved {
		t.Fatal("cross-port real observations remained trapped in single-port scope")
	}
	opts.MaxScopes = 1
	limited, err := svc.EvaluateSnapshotFacts(ctx, snap, assets, opts, evidence.DefaultConfig())
	if err != nil || limited.Reason != "snapshot_scope_budget_exceeded" || limited.Result != nil {
		t.Fatal("scope limit produced partial conclusions")
	}
}

func TestWireFrameRecoveryAndConflicts(t *testing.T) {
	wire := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("203.0.113.2")}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 10, ACK: true, Ack: 20, Window: 1000}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	ether := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ether, ip, tcp, gopacket.Payload(wire)); err != nil {
		t.Fatal(err)
	}
	i, h, m := protocolFixture(t, string(wire), true)
	m["src_ip"], m["dst_ip"], m["src_port"], m["dst_port"] = "192.0.2.1", "203.0.113.2", 1234, 80
	packet := m["raw_packet"].(map[string]any)
	delete(packet, "payload_hex")
	packet["packet_hex"] = hex.EncodeToString(buffer.Bytes())
	manifest := SnapshotEvidenceManifest{}
	enrichSnapshotProtocols(&i, h, m, &manifest)
	if i.HTTP == nil || i.HTTP.Records[0].Truncated {
		t.Fatalf("full frame not recovered: %+v", manifest)
	}
	m["dst_port"] = 81
	_, reason := snapshotFramePayload(packet, m, &i)
	if reason != "packet_flow_tuple_conflict" {
		t.Fatal("different flow frame accepted")
	}
}

func TestRedactedEncodingFeaturesStillFeedFactRule(t *testing.T) {
	body := "data=4142434445464748"
	wire := fmt.Sprintf("POST / HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	i, h, m := protocolFixture(t, wire, true)
	manifest := SnapshotEvidenceManifest{}
	enrichSnapshotProtocols(&i, h, m, &manifest)
	proof := evidence.Provenance{Verified: true, Complete: true, Version: "test-proof", SourceIDs: []string{h.ID}}
	i.HTTP.Provenance = proof
	i.Baselines = []evidence.Baseline{{Provenance: proof, FactID: "F_HTTP_FIELD_ENCODING", Metrics: map[string]float64{"encoded_field_ratio_p95": 0.1, "encoded_field_length_p95": 4}}}
	engine, _ := evidence.NewEngine(evidence.DefaultConfig())
	result, err := engine.Evaluate(context.Background(), evidence.Request{EventID: "e", SnapshotVersion: 1, Hits: []evidence.Hit{{ID: h.ID, Scope: i.Scope, OccurredAt: h.OccurredAt}}, Inputs: []evidence.Input{i}, Facts: []evidence.FactID{"F_HTTP_FIELD_ENCODING"}})
	if err != nil || result.Findings[0].Status != evidence.Observed {
		t.Fatalf("redaction destroyed safe features: %v %+v", err, result)
	}
	raw, _ := json.Marshal(i)
	if strings.Contains(string(raw), "4142434445464748") {
		t.Fatal("reversible value retained")
	}
}
