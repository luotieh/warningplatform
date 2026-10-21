package service

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

func TestPhaseOneSYNHTTPConnectionDedup(t *testing.T) {
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	for _, kind := range []string{"matched", "different-flow", "different-session", "different-sequence", "different-ioc", "different-device", "missing-session", "request-before-syn", "sequence-wrap", "multiple-requests", "syn-retransmission"} {
		t.Run(kind, func(t *testing.T) {
			scope := evidence.Scope{AssetID: "a", DeviceID: "d", EndpointID: "tcp://203.0.113.2:80"}
			syn := PhaseOneContact{ID: "syn", HitID: "syn-hit", Kind: "tcp_initiation", Time: at, Scope: scope, IOCType: "ip", IOCValue: "203.0.113.2", TCP: &PhaseOneTCPContact{FlowID: "verified-flow", Sequence: 10, SessionStart: &at}}
			req := syn
			req.ID, req.HitID, req.Kind, req.Time = "request", "request-hit", "complete_http_request", at.Add(time.Second)
			req.TCP = &PhaseOneTCPContact{FlowID: "verified-flow", Sequence: 11, SessionStart: &at}
			want := 2
			switch kind {
			case "matched", "multiple-requests", "syn-retransmission":
				want = 1
			case "different-flow":
				req.TCP.FlowID = "other-verified-flow"
			case "different-session":
				start := at.Add(-time.Hour)
				req.TCP.SessionStart = &start
			case "different-sequence":
				req.TCP.Sequence = 100
			case "different-ioc":
				req.IOCValue = "203.0.113.3"
			case "different-device":
				req.Scope.DeviceID = "other-device"
			case "missing-session":
				req.TCP.SessionStart = nil
			case "request-before-syn":
				syn.Time = at.Add(2 * time.Second)
			case "sequence-wrap":
				syn.TCP.Sequence, req.TCP.Sequence, want = ^uint32(0), 0, 1
			}
			m := PhaseOneMaterials{Contacts: []PhaseOneContact{syn, req}}
			if kind == "multiple-requests" {
				extra := req
				extra.ID, extra.HitID, extra.Time = "request-2", "request-hit-2", at.Add(2*time.Second)
				extra.TCP = &PhaseOneTCPContact{FlowID: "verified-flow", Sequence: 100, SessionStart: &at}
				m.Contacts, want = append(m.Contacts, extra), 2
			}
			if kind == "syn-retransmission" {
				retry := syn
				retry.Time, retry.HitID = at.Add(2*time.Second), "syn-retry-hit"
				m.Contacts = append(m.Contacts, retry)
			}
			m = dedupPhaseOneContacts(m)
			if len(m.Contacts) != want || len(m.ScopeIncomplete) != 0 {
				t.Fatal("wrong contact ownership or invented coverage gap", len(m.Contacts), want, m.ScopeIncomplete)
			}
			if kind == "syn-retransmission" && m.DuplicateContacts != 1 {
				t.Fatal("SYN retransmission escaped deduplication")
			}
		})
	}
}

func TestPhaseOneContactDedupRetainsActualGaps(t *testing.T) {
	in := map[string][]string{"scope": {"syn_excluded_from_http_request_timeline", "capture_completeness_unverified", "capture_time_binding_invalid"}}
	m := dedupPhaseOneContacts(PhaseOneMaterials{ScopeIncomplete: in, CurrentIncomplete: in})
	if len(m.ScopeIncomplete["scope"]) != 2 || len(m.CurrentIncomplete["scope"]) != 2 || len(in["scope"]) != 3 {
		t.Fatal("actual gaps removed or source modified", m)
	}
}

func TestProviderContactDedupAfterPeerMerge(t *testing.T) {
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	scope := evidence.Scope{AssetID: "a", DeviceID: "d", EndpointID: "tcp://203.0.113.2:80"}
	syn := PhaseOneContact{ID: "syn", HitID: "syn-hit", Kind: "tcp_initiation", Time: at, Scope: scope, IOCType: "ip", IOCValue: "203.0.113.2", TCP: &PhaseOneTCPContact{FlowID: "verified-flow", Sequence: 10, SessionStart: &at}}
	req := syn
	req.ID, req.HitID, req.Kind, req.Time = "request", "request-hit", "complete_http_request", at.Add(time.Second)
	req.TCP = &PhaseOneTCPContact{FlowID: "verified-flow", Sequence: 11, SessionStart: &at}
	historical := syn
	historical.ID, historical.HitID, historical.Time = "history", "history-hit", at.Add(-24*time.Hour)
	in := SnapshotEvidenceInput{Manifest: SnapshotEvidenceManifest{PhaseOne: &PhaseOneMaterials{Contacts: []PhaseOneContact{syn, historical, req}, CurrentContacts: []PhaseOneContact{syn, req}}}}
	dedupProviderContactSets(&in)
	if len(in.Manifest.PhaseOne.Contacts) != 2 || len(in.Manifest.PhaseOne.CurrentContacts) != 1 || in.Manifest.PhaseOne.CurrentContacts[0].Kind != "complete_http_request" {
		t.Fatal("merged SYN was not reconciled or history leaked into current")
	}
}

func TestProviderTemporalSYNHTTPIndependentPopulations(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	messages := []map[string]any{}
	for i := 0; i < 20; i++ {
		start := at.Add(time.Duration(i) * time.Minute)
		seq := uint32(1000 + 1000*i)
		syn := phaseOneWire(t, start, seq, nil, false, true)
		req := providerTemporalMessage(t, start.Add(time.Second), seq+1)
		for _, message := range []map[string]any{syn, req} {
			nestedMap(message, "raw_packet")["session_start_time"] = start.Format(time.RFC3339Nano)
		}
		messages = append(messages, syn, req)
	}
	// Same endpoint, but a distinct session without an HTTP request must survive.
	extra := phaseOneWire(t, at.Add(time.Hour), 900000, nil, false, true)
	nestedMap(extra, "raw_packet")["session_start_time"] = at.Add(time.Hour).Format(time.RFC3339Nano)
	messages = append(messages, extra)
	phaseOneInstallSnapshot(t, s, "mixed", 1, messages)
	c, err := CollectEvidenceFromPlatform(context.Background(), s.Store.(store.EvidenceReader), "mixed", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	before := digest(c)
	b, _, err := PreprocessCollectedEvidence(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, contact := range b.Inputs.Manifest.PhaseOne.Contacts {
		counts[contact.Kind]++
		if contact.TCP == nil || contact.TCP.FlowID == "" || contact.TCP.SessionStart == nil {
			t.Fatal("wire connection identity missing")
		}
	}
	if counts["complete_http_request"] != 20 || counts["tcp_initiation"] != 1 || len(b.Inputs.Manifest.PhaseOne.ScopeIncomplete) != 0 || before != digest(c) {
		t.Fatal("connection ownership lost or source changed", counts, b.Inputs.Manifest.PhaseOne.ScopeIncomplete)
	}
	encoded := bytes.NewBuffer(nil)
	if err = EncodePreparedEvidence(encoded, b); err != nil {
		t.Fatal(err)
	}
	b, err = DecodePreparedEvidence(encoded)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, finding := range result.Evaluation.Result.Findings {
		if finding.FactID != "F_BEACON_JITTER" && finding.FactID != "F_FIXED_DAILY_WINDOW" {
			continue
		}
		seen[fmt.Sprint(finding.FactID, ":", finding.ObservationKind)] = true
		if finding.ReasonCode == evidence.UnverifiedCoverage || finding.Measurements.SampleCount > 20 {
			t.Fatal("mixed populations blocked or inflated temporal calculation", finding)
		}
		if finding.FactID == "F_BEACON_JITTER" && finding.ObservationKind == "complete_http_request" && finding.Eligibility != "eligible" {
			t.Fatal("HTTP timeline did not execute", finding)
		}
	}
	if len(seen) != 3 || !seen["F_FIXED_DAILY_WINDOW:event_occurrence"] {
		t.Fatal("independent population lost", seen)
	}
}
