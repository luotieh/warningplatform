package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

func providerTemporalMessage(t *testing.T, at time.Time, seq uint32) map[string]any {
	m := phaseOneWire(t, at, seq, phaseOneHTTP("cmd=id"), false, false)
	m["ioc"] = map[string]any{"ioc_type": m["ioc_type"], "ioc_value": m["ioc_value"]}
	m["app"] = map[string]any{"http_url": "http://agent.test/agent", "http_method": "POST"}
	delete(m, "ioc_type")
	delete(m, "ioc_value")
	// Let the preprocessor derive datagram completeness from the actual frame.
	delete(nestedMap(m, "raw_packet"), "capture_truncated")
	return m
}

func TestProviderTemporalHistoryBudgetAndScopeFilter(t *testing.T) {
	at := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	for _, kind := range []string{"budget", "foreign-device", "foreign-ioc"} {
		t.Run(kind, func(t *testing.T) {
			s := phaseOneFixture(t)
			phaseOneInstallSnapshot(t, s, "current", 1, []map[string]any{providerTemporalMessage(t, at, 100)})
			prior := at.Add(-24 * time.Hour)
			historical := providerTemporalMessage(t, prior, 200)
			if kind == "foreign-device" {
				historical["device_id"] = "another-sensor"
			}
			if kind == "foreign-ioc" {
				nestedMap(historical, "ioc")["ioc_value"] = "198.51.100.99"
			}
			phaseOneInstallSnapshot(t, s, "historical", 1, []map[string]any{historical, providerTemporalMessage(t, prior.Add(time.Minute), 300)})
			options := providerTestOptions(t)
			if kind == "budget" {
				options.MaxHits = 1
			}
			collection, err := CollectEvidenceFromPlatform(context.Background(), s.Store.(store.EvidenceReader), "current", options)
			if err != nil {
				t.Fatal(err)
			}
			bundle, _, err := PreprocessCollectedEvidence(context.Background(), collection)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "budget" {
				ref := collection.HistorySnapshots["historical"]
				if ref.Loaded || ref.Reason != "historical_traffic_budget_exceeded" || len(bundle.Inputs.Manifest.PhaseOne.Contacts) != 1 {
					t.Fatal("history budget ignored", ref.Reason)
				}
			} else if len(bundle.Inputs.Manifest.PhaseOne.Contacts) != 2 {
				t.Fatal("foreign contact accepted or valid history discarded", kind, len(bundle.Inputs.Manifest.PhaseOne.Contacts))
			}
		})
	}
}

func TestProviderTemporalWireContactsAndCrossDayReplay(t *testing.T) {
	ctx := context.Background()
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	messages := []map[string]any{}
	for i := 0; i < 20; i++ {
		messages = append(messages, providerTemporalMessage(t, at.Add(time.Duration(i)*time.Minute), uint32(1000+i*300)))
	}
	messages = append(messages, messages[0]) // another alert for the exact same request
	phaseOneInstallSnapshot(t, s, "current", 1, messages)
	for day := 1; day <= 3; day++ {
		id := fmt.Sprintf("prior-%d", day)
		prior := at.AddDate(0, 0, -day)
		phaseOneInstallSnapshot(t, s, id, 1, []map[string]any{providerTemporalMessage(t, prior, uint32(20000+day))})
		// The event projection lacks a usable device join, while its frozen
		// snapshot and actual packet independently retain the binding.
		event, _ := s.Store.GetEvent(id)
		fields := decodeEventContext(event.Context)
		delete(fields, "device_id")
		raw, _ := json.Marshal(fields)
		event.Context = string(raw)
		if _, ok := s.Store.UpdateEvent(id, map[string]any{"context": event.Context}); !ok {
			t.Fatal("event context update failed")
		}
	}
	collection, err := CollectEvidenceFromPlatform(ctx, s.Store.(store.EvidenceReader), "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(collection.HistoryCandidates) != 3 {
		t.Fatal("history candidates missing", len(collection.HistoryCandidates))
	}
	for _, ref := range collection.HistorySnapshots {
		if !ref.Loaded || len(ref.Hits) != 1 {
			t.Fatal("historical wire not collected", ref.Reason)
		}
	}
	before := digest(collection)
	bundle, audit, err := PreprocessCollectedEvidence(ctx, collection)
	if err != nil {
		t.Fatal(err)
	}
	m := bundle.Inputs.Manifest.PhaseOne
	if len(m.CurrentContacts) != 20 || len(m.Contacts) != 23 || m.DuplicateContacts != 1 {
		t.Fatalf("contacts: current=%d expanded=%d duplicates=%d diagnostics=%v", len(m.CurrentContacts), len(m.Contacts), m.DuplicateContacts, m.Diagnostics)
	}
	for _, contact := range m.Contacts {
		if contact.ID == "" || contact.Time.IsZero() || contact.Kind != "complete_http_request" || contact.IOCType != "ip" || contact.IOCValue != "203.0.113.2" || contact.Scope.AssetID != "asset-a" || contact.HitID == "" || contact.Snapshot.Version != 1 {
			t.Fatal("incomplete independent contact", contact)
		}
	}
	if len(bundle.History.Rows) != 3 || bundle.History.ExcludedCount != 0 {
		t.Fatal("wire-proven history join not recovered", bundle.History)
	}
	for _, check := range audit.HistoryChecks {
		if !check.Accepted || len(check.Reasons) != 0 {
			t.Fatal("stale history exclusion", check)
		}
	}
	if len(bundle.Inputs.Observations) != 21 || bundle.Inputs.Request.Inputs[0].HTTP.Records[0].Truncated {
		t.Fatal("verified HTTP observations lost")
	}
	if bundle.Inputs.Request.Quality.Coverage != evidence.CoveragePartial || m.Complete || m.CurrentComplete || !bundle.History.Truncated {
		t.Fatal("snapshot count promoted to communication coverage")
	}
	if m.TemporalWindowCoverage == nil || m.TemporalWindowCoverage.Basis != assumedTemporalWindowCoverage || !m.TemporalWindowCoverage.CurrentComplete || !m.TemporalWindowCoverage.Complete {
		t.Fatal("temporal window default missing", m.TemporalWindowCoverage)
	}
	if bundle.Inputs.Request.Inputs[0].HTTP.Complete {
		t.Fatal("temporal default changed HTTP coverage")
	}
	assumptionAudited := false
	for _, proof := range audit.CoverageProofs {
		if proof.Family == "contacts" {
			assumptionAudited = proof.WindowCoverageAssumption != nil && proof.WindowCoverageAssumption.Basis == assumedTemporalWindowCoverage
			if proof.CollectionCoverage || proof.Complete {
				t.Fatal("default assumption became verified capture coverage")
			}
		}
	}
	if !assumptionAudited {
		t.Fatal("window assumption missing from audit")
	}
	raw, _ := json.Marshal(collection)
	var detached EvidenceCollection
	if err = json.Unmarshal(raw, &detached); err != nil {
		t.Fatal(err)
	}
	replayed, _, err := PreprocessCollectedEvidence(ctx, detached)
	if err != nil || replayed.InputDigest != bundle.InputDigest || before != digest(collection) {
		t.Fatal("offline replay or source immutability failed", err)
	}
	encoded := bytes.NewBuffer(nil)
	if err = EncodePreparedEvidence(encoded, bundle); err != nil {
		t.Fatal(err)
	}
	bundle, err = DecodePreparedEvidence(encoded)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExecutePreparedEvidence(ctx, bundle, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal(err)
	}
	found := map[evidence.FactID]evidence.Finding{}
	for _, finding := range result.Evaluation.Result.Findings {
		if finding.FactID == evidence.MultiDayPersist || finding.FactID == "F_FIXED_DAILY_WINDOW" || finding.FactID == "F_BEACON_JITTER" {
			found[finding.FactID] = finding
		}
	}
	if found[evidence.MultiDayPersist].Status != evidence.Observed {
		t.Fatal("cross-day positive lost under partial visibility", found)
	}
	for _, id := range []evidence.FactID{"F_FIXED_DAILY_WINDOW", "F_BEACON_JITTER"} {
		if found[id].Eligibility != "eligible" || !strings.Contains(strings.Join(found[id].Limitations, ";"), "observation_window_assumed_complete") {
			t.Fatal("default window did not reach temporal calculation or lost assumption", id, found[id])
		}
	}
	t.Logf("20 current contacts / 4 days: jitter and fixed-daily execute with an explicit window assumption; verified capture and HTTP coverage remain partial")
}

func TestProviderTemporalWindowDefaultKeepsKnownGaps(t *testing.T) {
	at := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	for _, kind := range []string{"truncated-current", "truncated-history", "history-budget", "history-query-truncated", "few-samples"} {
		t.Run(kind, func(t *testing.T) {
			s := phaseOneFixture(t)
			messages := []map[string]any{}
			n := 20
			if kind == "few-samples" {
				n = 1
			}
			for i := 0; i < n; i++ {
				messages = append(messages, providerTemporalMessage(t, at.Add(time.Duration(i)*time.Minute), uint32(1000+i*300)))
			}
			if kind == "truncated-current" {
				bad := providerTemporalMessage(t, at.Add(time.Hour), 30000)
				nestedMap(bad, "raw_packet")["capture_truncated"] = true
				messages = append(messages, bad)
			}
			phaseOneInstallSnapshot(t, s, "current", 1, messages)
			for day := 1; day <= 3; day++ {
				m := providerTemporalMessage(t, at.AddDate(0, 0, -day), uint32(40000+day))
				if kind == "truncated-history" && day == 1 {
					nestedMap(m, "raw_packet")["capture_truncated"] = true
				}
				phaseOneInstallSnapshot(t, s, fmt.Sprintf("prior-%d", day), 1, []map[string]any{m})
			}
			c, err := CollectEvidenceFromPlatform(context.Background(), s.Store.(store.EvidenceReader), "current", providerTestOptions(t))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "history-budget":
				ref := c.HistorySnapshots["prior-1"]
				ref.Hits, ref.Loaded, ref.Reason = nil, false, "historical_traffic_budget_exceeded"
				c.HistorySnapshots["prior-1"] = ref
			case "history-query-truncated":
				c.HistoryTruncated = true
			}
			c.Seal()
			b, _, err := PreprocessCollectedEvidence(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			result, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
			if err != nil {
				t.Fatal(err)
			}
			found := map[evidence.FactID]evidence.Finding{}
			for _, finding := range result.Evaluation.Result.Findings {
				if finding.FactID == "F_BEACON_JITTER" || finding.FactID == "F_FIXED_DAILY_WINDOW" {
					found[finding.FactID] = finding
				}
			}
			if kind == "few-samples" {
				if found["F_BEACON_JITTER"].ReasonCode != evidence.InsufficientSamples {
					t.Fatal("default fabricated samples", found)
				}
				return
			}
			if found["F_FIXED_DAILY_WINDOW"].ReasonCode != evidence.UnverifiedCoverage {
				t.Fatal("known gap was ignored", kind, found)
			}
			if kind == "truncated-current" {
				if found["F_BEACON_JITTER"].ReasonCode != evidence.UnverifiedCoverage {
					t.Fatal("truncated current window was promoted", found)
				}
			} else if found["F_BEACON_JITTER"].Eligibility != "eligible" {
				t.Fatal("historical gap erased complete current jitter samples", found)
			}
		})
	}
}

func TestProviderTemporalRejectsUnprovenAndForeignContacts(t *testing.T) {
	at := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	for _, kind := range []string{"wire-ioc-mismatch", "timestamp-mismatch", "truncated", "truncated-syn", "summary-only"} {
		t.Run(kind, func(t *testing.T) {
			s := phaseOneFixture(t)
			m := providerTemporalMessage(t, at, 100)
			if kind == "truncated-syn" {
				m = phaseOneWire(t, at, 100, nil, false, true)
				nestedMap(m, "raw_packet")["capture_truncated"] = true
			}
			switch kind {
			case "wire-ioc-mismatch":
				nestedMap(m, "ioc")["ioc_value"] = "198.51.100.99"
			case "timestamp-mismatch": // hit time is installed first; modify capture below
			case "truncated":
				nestedMap(m, "raw_packet")["capture_truncated"] = true
			case "summary-only":
				delete(m, "raw_packet")
				m["app"] = map[string]any{"http_url": "http://agent.test/agent", "http_method": "POST"}
			}
			if kind == "summary-only" { // snapshot fixture obtains timestamps from the packet
				m["raw_packet"] = map[string]any{"capture_time": at.Format(time.RFC3339Nano)}
			}
			snap := phaseOneInstallSnapshot(t, s, "current", 1, []map[string]any{m})
			collection, err := CollectEvidenceFromPlatform(context.Background(), s.Store.(store.EvidenceReader), "current", providerTestOptions(t))
			if err != nil {
				t.Fatal(err)
			}
			if kind == "timestamp-mismatch" {
				var fields map[string]any
				_ = json.Unmarshal(collection.Hits[0].Raw, &fields)
				nestedMap(fields, "raw_packet")["capture_time"] = at.Add(time.Second).Format(time.RFC3339Nano)
				collection.Hits[0].Raw, _ = json.Marshal(fields)
				collection.Seal()
			}
			bundle, _, err := PreprocessCollectedEvidence(context.Background(), collection)
			if err != nil {
				t.Fatal(err, snap.EventID)
			}
			if len(bundle.Inputs.Manifest.PhaseOne.Contacts) != 0 {
				t.Fatal("unproven communication accepted", kind)
			}
		})
	}
}
