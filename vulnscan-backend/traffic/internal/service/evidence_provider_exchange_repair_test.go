package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func exchangeTestPacket(t *testing.T, payload []byte, seq, ack uint32, at time.Time, reverse bool) map[string]any {
	t.Helper()
	src, dst, sp, dp := "192.0.2.1", "203.0.113.2", uint16(45000), uint16(80)
	if reverse {
		src, dst, sp, dp = dst, src, dp, sp
	}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), Seq: seq, Ack: ack, ACK: true, Window: 8192}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"packet_hex": hex.EncodeToString(b.Bytes()), "payload_hex": hex.EncodeToString(payload), "capture_time": at.Format(time.RFC3339Nano), "capture_time_usec": at.UnixMicro(), "captured_length": len(b.Bytes()), "wire_length": len(b.Bytes()), "tcp_seq": seq, "tcp_ack": ack}
}

func exchangeTestFixture(t *testing.T) (map[string]any, evidence.Input, store.Hit, []domain.Asset) {
	t.Helper()
	at := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	request := phaseOneHTTP("user=alice&password=secret")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nok\n")
	cut := len(request) - 10
	p1 := exchangeTestPacket(t, request[:cut], 100, 500, at, false)
	p2 := exchangeTestPacket(t, request[cut:], 100+uint32(cut), 500, at.Add(time.Millisecond), false)
	r := exchangeTestPacket(t, response, 500, 100+uint32(len(request)), at.Add(2*time.Millisecond), true)
	m := map[string]any{"src_ip": "192.0.2.1", "dst_ip": "203.0.113.2", "src_port": 45000, "dst_port": 80, "protocol": "tcp", "device_id": "node-a", "session_id": "session-a", "transaction_id": "txn-a", "ioc_type": "ip", "ioc_value": "203.0.113.2", "raw_packet": p1, "exchange": map[string]any{"response_status": "complete", "request": map[string]any{"reassembled_hex": hex.EncodeToString(request), "packets": []any{p1, p2}}, "response": map[string]any{"reassembled_hex": hex.EncodeToString(response), "packets": []any{r}}}}
	// Use the exact JSON representation consumed by collection/preprocessing.
	raw, _ := json.Marshal(m)
	m = map[string]any{}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		t.Fatal(err)
	}
	in := evidence.Input{Scope: evidence.Scope{AssetID: "asset", DeviceID: "node-a", EndpointID: "tcp://203.0.113.2:80"}, Window: &evidence.AnalysisWindow{Start: at.Add(-time.Second), End: at.Add(time.Second)}}
	h := store.Hit{ID: "exchange-hit", OccurredAt: at, Raw: raw}
	assets := []domain.Asset{{ID: "asset", Address: "192.0.2.1", Status: 1}}
	return m, in, h, assets
}

func TestProviderExchangeVerifiedMaterialsAndContact(t *testing.T) {
	m, in, h, assets := exchangeTestFixture(t)
	source := append([]byte(nil), h.Raw...)
	x := providerVerifiedHTTP(m)
	if x == nil || x.Request == nil || x.Response == nil || x.FrameDecodes != 3 {
		t.Fatalf("verified exchange missing: %+v", x)
	}
	if providerVerifiedHTTP(m) != x || x.FrameDecodes != 3 {
		t.Fatal("validation not reused")
	}
	adaptSnapshotProtocols(&in, h, m, "203.0.113.2", 80, false)
	out := SnapshotEvidenceInput{Manifest: SnapshotEvidenceManifest{PhaseOne: &PhaseOneMaterials{}}, Request: evidence.Request{Hits: []evidence.Hit{{ID: h.ID, Scope: in.Scope, OccurredAt: h.OccurredAt}}}}
	enrichSnapshotProtocols(&in, h, m, &out.Manifest)
	if in.HTTP == nil || len(in.HTTP.Records) != 1 {
		t.Fatal("HTTP missing", out.Manifest)
	}
	r := in.HTTP.Records[0]
	if r.Truncated || !r.ResponseVerified || r.ResponseStatus != 200 || r.BodyLength == nil || r.Fields["password"] != "[redacted]" || r.RequestID == "" {
		t.Fatalf("lost parsed material %+v", r)
	}
	if in.HTTP.Complete {
		t.Fatal("one transaction promoted entire window")
	}
	collectSnapshotSemanticObservation(&out, &in, h, m, assets)
	if len(out.SemanticObservations) != 1 || !out.SemanticObservations[0].Complete || out.SemanticObservations[0].Response == "" {
		t.Fatal("semantic response missing", out.SemanticObservations)
	}
	snap := EvidenceSnapshot{EventID: "e", Version: 1}
	appendProviderExchangeContact(&out.Manifest, h, m, in, assets, snap)
	appendProviderExchangeContact(&out.Manifest, h, m, in, assets, snap)
	if len(out.Manifest.PhaseOne.Contacts) != 1 || !out.Manifest.PhaseOne.Contacts[0].Time.Equal(h.OccurredAt) {
		t.Fatal("contact lost or duplicated", out.Manifest.PhaseOne.Contacts)
	}
	if string(h.Raw) != string(source) {
		t.Fatal("stored raw changed")
	}
	out.Request.Inputs = []evidence.Input{in}
	req := buildSnapshotSemanticRequest(snap, out, &evidence.Result{}, evidence.SemanticRaw)
	req.Slots = []evidence.SlotKey{{ID: "S02", Target: "c2.command_exchange"}}
	e, err := evidence.NewSemanticEngine(evidence.DefaultSemanticConfig())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := e.Plan(context.Background(), req)
	if err != nil || len(plan.Tasks) != 1 {
		for _, s := range req.Subjects {
			for _, m := range s.Materials {
				t.Logf("material %s %s truncated=%v proof=%+v", s.ID, m.Kind, m.Truncated, m.Provenance)
			}
		}
		t.Fatal("pair not executable", err, plan)
	}
	calls := 0
	result, err := e.Evaluate(context.Background(), req, reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		calls++
		return acceptedSemanticResponse(t, call), nil
	}))
	if err != nil || calls != 1 || len(result.Findings) != 1 || result.Findings[0].StructureValidation != "passed" || result.Findings[0].BehaviorOutcome != "not_established" {
		t.Fatal("controlled S02 failed", err, result)
	}
}

func TestProviderExchangeRejectsUnverifiedSources(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		mutate                func(map[string]any)
		requestOK, responseOK bool
	}{
		{"missing_request", func(m map[string]any) { delete(nestedMap(m, "exchange"), "request") }, false, false},
		{"status_alone", func(m map[string]any) { delete(nestedMap(nestedMap(m, "exchange"), "request"), "packets") }, false, false},
		{"truncated", func(m map[string]any) { nestedMap(nestedMap(m, "exchange"), "request")["truncated"] = true }, false, false},
		{"reassembly_gap_flag", func(m map[string]any) { nestedMap(nestedMap(m, "exchange"), "request")["reassembly_incomplete"] = true }, false, false},
		{"reassembly_conflict", func(m map[string]any) { nestedMap(nestedMap(m, "exchange"), "request")["reassembled_hex"] = "47455420" }, false, false},
		{"payload_conflict", func(m map[string]any) {
			ps := nestedMap(nestedMap(m, "exchange"), "request")["packets"].([]any)
			ps[0].(map[string]any)["payload_hex"] = "00"
		}, false, false},
		{"flow_conflict", func(m map[string]any) { m["dst_ip"] = "203.0.113.9" }, false, false},
		{"packet_time_conflict", func(m map[string]any) {
			ps := nestedMap(nestedMap(m, "exchange"), "request")["packets"].([]any)
			ps[0].(map[string]any)["capture_time"] = "2026-10-20T00:00:00Z"
		}, false, false},
		{"response_seq_conflict", func(m map[string]any) {
			ps := nestedMap(nestedMap(m, "exchange"), "response")["packets"].([]any)
			ps[0].(map[string]any)["tcp_ack"] = 1
		}, true, false},
		{"response_truncated", func(m map[string]any) { nestedMap(nestedMap(m, "exchange"), "response")["truncated"] = true }, true, false},
		{"no_response", func(m map[string]any) { delete(nestedMap(m, "exchange"), "response") }, true, false},
		{"no_txn", func(m map[string]any) { delete(m, "transaction_id") }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _, _ := exchangeTestFixture(t)
			tc.mutate(m)
			x := providerVerifiedHTTP(m)
			requestOK := x != nil && x.Request != nil
			responseOK := x != nil && x.Response != nil
			if requestOK != tc.requestOK || responseOK != tc.responseOK {
				t.Fatalf("unexpected acceptance %+v", x)
			}
		})
	}
}

func TestProviderExchangeOutOfOrderRetransmissionAndWindow(t *testing.T) {
	m, in, h, assets := exchangeTestFixture(t)
	q := nestedMap(nestedMap(m, "exchange"), "request")
	ps := q["packets"].([]any)
	q["packets"] = []any{ps[1], ps[0], ps[0]}
	x := providerVerifiedHTTP(m)
	if x == nil || x.Request == nil || x.Response == nil {
		t.Fatal("exact out-of-order/retransmission not recovered", x)
	}
	adaptSnapshotProtocols(&in, h, m, "203.0.113.2", 80, false)
	manifest := SnapshotEvidenceManifest{PhaseOne: &PhaseOneMaterials{}}
	enrichSnapshotProtocols(&in, h, m, &manifest)
	in.Window.Start = h.OccurredAt.Add(time.Millisecond)
	appendProviderExchangeContact(&manifest, h, m, in, assets, EvidenceSnapshot{EventID: "e", Version: 1})
	if len(manifest.PhaseOne.Contacts) != 0 {
		t.Fatal("prior-window request used as current contact")
	}
}

func TestProviderExchangeSameRequestNeverAddsHitSamples(t *testing.T) {
	m, in, h, assets := exchangeTestFixture(t)
	adaptSnapshotProtocols(&in, h, m, "203.0.113.2", 80, false)
	manifest := SnapshotEvidenceManifest{PhaseOne: &PhaseOneMaterials{}}
	enrichSnapshotProtocols(&in, h, m, &manifest)
	appendProviderExchangeContact(&manifest, h, m, in, assets, EvidenceSnapshot{EventID: "e", Version: 1})
	if len(manifest.PhaseOne.Contacts) != 1 {
		t.Fatal("first contact missing")
	}
	original := manifest.PhaseOne.Contacts[0]
	// A later hit/retransmission projects the same request, with a different
	// legacy start time. Its trigger sequence is not the request sequence.
	other := h
	other.ID = "response-hit"
	other.OccurredAt = h.OccurredAt.Add(10 * time.Millisecond)
	r := in.HTTP.Records[0]
	r.SourceID = other.ID
	in.HTTP.Records = append(in.HTTP.Records, r)
	legacy := original
	legacy.HitID = other.ID
	legacy.ID = "wrong-response-trigger-id"
	legacy.Time = other.OccurredAt
	tcp := *legacy.TCP
	tcp.Sequence = 500
	legacy.TCP = &tcp
	syn := legacy
	syn.Kind = "tcp_initiation"
	syn.ID = "unrelated-syn"
	manifest.PhaseOne.Contacts = append(manifest.PhaseOne.Contacts, legacy, syn)
	nestedMap(m, "raw_packet")["session_start_time"] = h.OccurredAt.Add(-time.Millisecond).Format(time.RFC3339Nano)
	appendProviderExchangeContact(&manifest, other, m, in, assets, EvidenceSnapshot{EventID: "e", Version: 1})
	if len(manifest.PhaseOne.Contacts) != 2 || manifest.PhaseOne.Contacts[0].ID != original.ID || manifest.PhaseOne.Contacts[1].Kind != "tcp_initiation" {
		t.Fatal("duplicate hit counted or old contact/SYN identity changed", manifest.PhaseOne.Contacts)
	}
	if len(manifest.PhaseOne.Bindings) != 2 {
		t.Fatal("duplicate identity lost source binding")
	}
}

func TestSemanticTypedHistoryProjectionPreservesIdentity(t *testing.T) {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	scope := evidence.Scope{AssetID: "asset", DeviceID: "device", EndpointID: "endpoint"}
	w := evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)}
	legacy := evidence.Finding{FactID: "F_HIST_INFRA_PERSISTENCE", Scope: scope, Window: &evidence.Window{Start: w.Start, End: w.End}, SnapshotVersion: 1, Status: evidence.Missing}
	ip, domainFact := legacy, legacy
	ip.IOCType, ip.IOCValue, ip.ObservationKind = "ip", "192.0.2.1", "event_occurrence"
	domainFact.IOCType, domainFact.IOCValue, domainFact.ObservationKind = "domain", "example.test", "event_occurrence"
	other := legacy
	other.FactID = "F_BEACON_JITTER"
	snapshot := EvidenceSnapshot{EventID: "event", Version: 1}
	in := SnapshotEvidenceInput{Request: evidence.Request{Inputs: []evidence.Input{{Scope: scope, Window: &w}}}}
	for _, prepared := range []bool{false, true} {
		for _, typed := range []bool{false, true} {
			fs := []evidence.Finding{legacy, other}
			if typed {
				fs = []evidence.Finding{ip, domainFact, other}
			}
			result := &evidence.Result{Findings: fs}
			before := digest(result)
			input := in
			if prepared {
				r := buildSnapshotSemanticRequest(snapshot, input, &evidence.Result{}, evidence.SemanticRaw)
				input.PreparedSemantics = &r
			}
			r := buildSnapshotSemanticRequest(snapshot, input, result, evidence.SemanticRaw)
			if len(r.Subjects) != 1 {
				t.Fatalf("unexpected subjects: %d", len(r.Subjects))
			}
			want := 2
			if typed {
				want = 1
			}
			if len(r.Subjects[0].Facts) != want {
				t.Fatalf("prepared=%v typed=%v facts=%d", prepared, typed, len(r.Subjects[0].Facts))
			}
			if digest(result) != before {
				t.Fatal("semantic projection mutated typed algorithm output")
			}
			for _, f := range r.Subjects[0].Facts {
				if f.IOCType != "" {
					t.Fatal("typed IOC lost its reference identity")
				}
			}
		}
	}
}

// Replays the frozen provider collections, not edited model responses or F outputs.
func TestProviderSemanticTypedHistoryPipeline(t *testing.T) {
	root := os.Getenv("PROVIDER_BINDING_COLLECTION_ROOT")
	if root == "" {
		t.Skip("optional frozen synthetic provider collections")
	}
	for _, scenario := range []string{"c2", "botnet", "phishing", "network-activity"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(root, "provider-"+scenario+"-stub", "attempt-01", "platform-collection.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var c EvidenceCollection
			if err = json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			before := digest(c)
			b, audit, err := PreprocessCollectedEvidence(context.Background(), c)
			if err != nil || !audit.Valid {
				t.Fatal(err, audit.Valid)
			}
			result, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticStub, SemanticModel: reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
				return acceptedSemanticResponse(t, call), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			if result.Semantics.Result == nil {
				t.Fatalf("semantic pipeline unavailable: status=%s reason=%s", result.Semantics.Status, result.Semantics.Reason)
			}
			typed := map[string]bool{}
			for _, f := range result.Evaluation.Result.Findings {
				if f.FactID == "F_HIST_INFRA_PERSISTENCE" && f.IOCType != "" {
					typed[f.IOCType+":"+f.IOCValue] = true
				}
			}
			if scenario == "c2" && len(typed) < 2 {
				t.Fatalf("multi-IOC F findings lost: %v", typed)
			}
			normalized := map[string]bool{}
			for _, f := range result.Evidence.Normalized.Items {
				if f.RuleID == "F_HIST_INFRA_PERSISTENCE" && f.IOCType != "" {
					normalized[f.IOCType+":"+f.IOCValue] = true
				}
			}
			if digest(typed) != digest(normalized) {
				t.Fatal("typed F identity lost in normalized output")
			}
			s15 := 0
			for _, f := range result.Semantics.Result.Findings {
				if f.Slot.ID == "S15" {
					s15++
				}
			}
			if s15 == 0 {
				t.Fatal("original S15 explanation no longer executable")
			}
			if digest(c) != before {
				t.Fatal("frozen collection mutated")
			}
			t.Logf("typed_infra_subjects=%d S15=%d semantic_status=%s", len(typed), s15, result.Semantics.Status)
		})
	}
}

// Optional immutable real collection replay. Logs restore counts without
// asserting that all platform traffic or a semantic attack outcome is known.
func TestProviderExchangeRealFrozenCollection(t *testing.T) {
	path := os.Getenv("PROVIDER_EXCHANGE_COLLECTION")
	if path == "" {
		t.Skip("optional archived real collection")
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var c EvidenceCollection
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	before := digest(c)
	b, a, err := PreprocessCollectedEvidence(context.Background(), c)
	if err != nil || !a.Valid {
		t.Fatal(err, a.Valid)
	}
	if digest(c) != before {
		t.Fatal("real immutable collection mutated")
	}
	records, verified, bodyKnown, completeFamilies, semanticPairs := 0, 0, 0, 0, 0
	for _, in := range b.Inputs.Request.Inputs {
		if in.HTTP == nil {
			continue
		}
		records += len(in.HTTP.Records)
		if in.HTTP.Complete {
			completeFamilies++
		}
		for _, r := range in.HTTP.Records {
			if r.ResponseVerified {
				verified++
			}
			if r.BodyLength != nil && !r.Truncated {
				bodyKnown++
			}
		}
	}
	for _, o := range b.Inputs.Observations {
		if o.HTTP != nil && o.HTTP.ResponseVerified && o.Response != "" {
			semanticPairs++
		}
	}
	contacts := map[string]int{}
	physical := map[string]int{}
	firstContact := map[string]PhaseOneContact{}
	loggedDuplicate := false
	for _, x := range b.Inputs.Manifest.PhaseOne.Contacts {
		contacts[x.Kind]++
		if x.TCP != nil {
			key := fmt.Sprintf("%v:%s:%s:%d", x.Scope, x.Kind, x.TCP.FlowID, x.TCP.Sequence)
			physical[key]++
			if old, exists := firstContact[key]; exists && !loggedDuplicate {
				t.Logf("duplicate_contact old=%+v oldTCP=%+v new=%+v newTCP=%+v", old, old.TCP, x, x.TCP)
				loggedDuplicate = true
			} else {
				firstContact[key] = x
			}
		}
	}
	t.Logf("event=%s hits=%d records=%d verified_responses=%d complete_request_bodies=%d complete_http_families=%d semantic_pairs=%d contacts=%v", c.Snapshot.EventID, len(c.Hits), records, verified, bodyKnown, completeFamilies, semanticPairs, contacts)
	duplicates := 0
	for _, n := range physical {
		if n > 1 {
			duplicates += n - 1
		}
	}
	t.Logf("same_flow_seq_contacts=%d", duplicates)
	reasons := map[string]int{}
	for _, h := range c.Hits {
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(string(h.Raw)))
		d.UseNumber()
		_ = d.Decode(&m)
		x := providerVerifiedHTTP(m)
		if x != nil {
			reasons["req:"+x.RequestProblem]++
			if x.Request != nil {
				reasons["resp:"+x.ResponseProblem]++
			}
		}
	}
	t.Logf("exchange_validation=%v", reasons)
	result, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticStub, SemanticModel: reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		return acceptedSemanticResponse(t, call), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Evaluation.Result.Findings {
		if strings.HasPrefix(string(f.FactID), "F_HTTP") || f.FactID == "F_CRED_POST_STRUCTURE" || f.FactID == "F_FORM_CROSSSITE" {
			t.Logf("F %s %s %s samples=%d", f.FactID, f.Status, f.ReasonCode, f.Measurements.SampleCount)
		}
	}
	if result.Semantics.Result != nil {
		counts := map[string]int{}
		for _, f := range result.Semantics.Result.Findings {
			counts[fmt.Sprintf("%s:%s:%s", f.Slot.String(), f.StructureValidation, f.BehaviorOutcome)]++
		}
		t.Logf("S_counts=%v", counts)
		skips := []string{}
		for _, x := range result.Semantics.Result.Plan.Executions {
			if x.Slot.ID == "S03" && x.Reason == "task_budget_exceeded" {
				skips = append(skips, x.SubjectID)
			}
		}
		t.Logf("S03_budget_skipped_count=%d subject_ids=%s", len(skips), strings.Join(skips, ","))
	}
	if beforePath := os.Getenv("PROVIDER_EXCHANGE_BEFORE_BUNDLE"); beforePath != "" {
		beforeRaw, err := os.ReadFile(filepath.Clean(beforePath))
		if err != nil {
			t.Fatal(err)
		}
		var beforeBundle PreparedEvidenceBundle
		if err = json.Unmarshal(beforeRaw, &beforeBundle); err != nil {
			t.Fatal(err)
		}
		if beforeBundle.Snapshot.EventID != b.Snapshot.EventID {
			t.Fatal("wrong before event")
		}
		oldOps := map[string]string{}
		for _, o := range beforeBundle.Inputs.Observations {
			oldOps[o.HitID] = o.Payload
		}
		newOps := map[string]string{}
		for _, o := range b.Inputs.Observations {
			newOps[o.HitID] = o.Payload
		}
		if digest(oldOps) != digest(newOps) {
			t.Fatal("legacy semantic operation identities/bytes changed")
		}
		cfg := b.SemanticOptions.Config
		cfg.ReportPractical = true
		engine, err := evidence.NewSemanticEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		counts := []int{}
		for _, source := range []PreparedEvidenceBundle{beforeBundle, b} {
			r := buildSnapshotSemanticRequest(source.Snapshot, restorePreparedInputs(source.Inputs), &evidence.Result{}, source.SemanticOptions.InputMode)
			r.Slots = []evidence.SlotKey{{ID: "S03", Target: "c2.ua_behavior_conflict"}}
			plan, err := engine.Plan(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			counts = append(counts, len(plan.Tasks))
		}
		if counts[0] != counts[1] {
			t.Fatalf("S03 material eligibility regressed: %v", counts)
		}
		if len(oldOps) > 0 && counts[0] == 0 {
			t.Fatal("S03 diagnostic planned no real materials")
		}
		t.Logf("preserved_operations=%d S03_only_same_max_tasks=%d before_planned=%d after_planned=%d", len(oldOps), cfg.MaxTasks, counts[0], counts[1])
	}
}
