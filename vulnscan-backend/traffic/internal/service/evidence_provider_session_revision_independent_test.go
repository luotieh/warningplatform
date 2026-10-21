package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Synthetic integration: preserve the producer's original event/packet time
// while a later revision enriches that same hit with a cumulative summary.
// This is not a new real capture or a claim of complete network observation.
func TestIndependentSessionRevisionSurvivesOccurrenceWindow(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	svc := Services{Store: st}
	if _, err := st.CreateAsset(domain.Asset{ID: "revision-asset", Address: "192.0.2.1", Status: 1}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	m := phaseOneWire(t, at, 1, nil, false, true)
	m["event_id"], m["event_type"], m["rule_id"] = "original-producer-event", "c2", "revision-rule"
	m["context_revision"] = 1
	m["session_summary"] = map[string]any{"first_time_usec": at.UnixMicro(), "last_time_usec": at.UnixMicro(), "client_packets": 1, "client_wire_bytes": 74, "hit_count": 1}
	accepted, err := svc.ProcessLyEvent(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	id := asString(accepted["deepsoc_event_id"])
	if id == "" {
		t.Fatal("initial ingest rejected", accepted)
	}
	if err = svc.DrainAggregation(ctx, 20); err != nil {
		t.Fatal(err)
	}
	before, err := CollectEvidenceFromPlatform(ctx, st, id, providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	oldPrepared, _, err := PreprocessCollectedEvidence(ctx, before)
	if err != nil || len(providerSessionRecords(restorePreparedInputs(oldPrepared.Inputs))) != 1 {
		t.Fatal("initial summary control failed", err, oldPrepared.Inputs.Manifest.Issues)
	}
	packetBefore, _ := json.Marshal(m["raw_packet"])
	m["context_revision"] = 2
	m["session_summary"] = map[string]any{"first_time_usec": at.UnixMicro(), "last_time_usec": at.Add(30 * time.Second).UnixMicro(), "client_packets": 3, "server_packets": 2, "client_wire_bytes": 222, "server_wire_bytes": 108, "hit_count": 1}
	updated, err := svc.ProcessLyEvent(ctx, m)
	if err != nil || updated["ingest_status"] != "evidence_updated" {
		t.Fatal("revision rejected", updated, err)
	}
	if err = svc.DrainAggregation(ctx, 20); err != nil {
		t.Fatal(err)
	}
	after, err := CollectEvidenceFromPlatform(ctx, st, id, providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Hits) != 1 || after.Snapshot.Count != 1 || !after.Hits[0].OccurredAt.Equal(at) || after.Snapshot.RevisionWatermark <= before.Snapshot.RevisionWatermark || after.Snapshot.Version <= before.Snapshot.Version || !after.Window.Start.Equal(at) || !after.Window.End.Equal(at.Add(time.Nanosecond)) {
		t.Fatal("revision changed occurrence membership/time/window", after.Snapshot, after.Window, after.Hits)
	}
	var saved map[string]any
	if err = json.Unmarshal(after.Hits[0].Raw, &saved); err != nil {
		t.Fatal(err)
	}
	packetAfter, _ := json.Marshal(saved["raw_packet"])
	if string(packetBefore) != string(packetAfter) || toInt(saved["event_time"]) != int(at.UnixMicro()) || toInt(nestedMap(saved, "session_summary")["last_time_usec"]) == 0 {
		t.Fatal("collector lost original packet/event time or latest summary")
	}
	b, _, err := PreprocessCollectedEvidence(ctx, after)
	if err != nil {
		t.Fatal(err)
	}
	sessions := providerSessionRecords(restorePreparedInputs(b.Inputs))
	t.Logf("synthetic=true before_version=%d after_version=%d revision_watermark=%d hits=%d window=[%s,%s) summary_end=%s sessions=%d issues=%+v", before.Snapshot.Version, after.Snapshot.Version, after.Snapshot.RevisionWatermark, len(after.Hits), after.Window.Start, after.Window.End, at.Add(30*time.Second), len(sessions), b.Inputs.Manifest.Issues)
	if len(sessions) != 1 || !sessions[0].End.Equal(at.Add(30*time.Second)) || sessions[0].UpBytes != 222 || sessions[0].DownBytes != 108 || sessions[0].VolumeVerified || !sessions[0].ObservationOnly || sessions[0].ByteUnit != "wire" {
		t.Fatal("latest source-bound observation-only summary lost at preprocessing", sessions)
	}
	for _, in := range b.Inputs.Request.Inputs {
		if in.Network.Complete || in.Window == nil || !in.Window.Start.Equal(before.Window.Start) || !in.Window.End.Equal(before.Window.End) {
			t.Fatal("session revision widened algorithm window or network authority", in)
		}
	}
	if len(b.Inputs.Manifest.PhaseOne.Contacts) != len(oldPrepared.Inputs.Manifest.PhaseOne.Contacts) {
		t.Fatal("summary revision created contact samples")
	}
	contactIdentity := func(contacts []PhaseOneContact) string {
		out := append([]PhaseOneContact{}, contacts...)
		for i := range out {
			out[i].Snapshot.Version = 0
			out[i].Snapshot.RevisionWatermark = 0
		}
		return digest(out)
	}
	if contactIdentity(b.Inputs.Manifest.PhaseOne.CurrentContacts) != contactIdentity(oldPrepared.Inputs.Manifest.PhaseOne.CurrentContacts) {
		t.Fatal("summary revision changed independent current contact identity/time")
	}
	beforeExecution, err := ExecutePreparedEvidence(ctx, oldPrepared, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal("initial complete execution failed", err)
	}
	afterExecution, err := ExecutePreparedEvidence(ctx, b, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal("revised complete execution failed", err)
	}
	temporal := func(ex PreparedEvidenceExecution) map[evidence.FactID][]string {
		out := map[evidence.FactID][]string{}
		all := append([]evidence.Finding{}, ex.Evaluation.Result.Findings...)
		all = append(all, ex.Evidence.PhaseOne.Facts...)
		for _, finding := range all {
			switch finding.FactID {
			case "F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW", "F_MULTI_DAY_PERSIST":
				// Snapshot identity must change, while the evidence supplied to
				// these temporal rules and their actual decisions must not.
				out[finding.FactID] = append(out[finding.FactID], digest([]any{finding.Scope, finding.IOCType, finding.IOCValue, finding.ObservationKind, finding.Window, finding.Status, finding.Eligibility, finding.Quality, finding.Measurements, finding.Parameters, finding.SourceIDs, finding.ReasonCode, finding.Limitations}))
			}
		}
		return out
	}
	oldTime, newTime := temporal(beforeExecution), temporal(afterExecution)
	if len(oldTime) != 3 || digest(oldTime) != digest(newTime) {
		t.Fatal("reported summary changed temporal algorithm evidence or decisions", oldTime, newTime)
	}
	t.Log("three temporal facts unchanged; original contacts/window unchanged; revised reported span retained without volume authority")
	oldAgain, _, err := PreprocessCollectedEvidence(ctx, before)
	if err != nil || digest(providerSessionRecords(restorePreparedInputs(oldAgain.Inputs))) != digest(providerSessionRecords(restorePreparedInputs(oldPrepared.Inputs))) {
		t.Fatal("later revision contaminated frozen older collection", err)
	}
}
