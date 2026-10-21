package service

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

func TestProviderSessionResultCacheRejectsPreviousPreprocessing(t *testing.T) {
	for _, prior := range []string{"unversioned-result", "real-chain-parity-2"} {
		t.Run(prior, func(t *testing.T) {
			ctx := context.Background()
			s := phaseOneFixture(t)
			sem := DefaultReportSemanticOptions()
			sem.Disable = true
			s.ReportSemantics = &sem
			at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
			snap := phaseOneInstallSnapshot(t, s, "session-cache-"+prior, 1, []map[string]any{phaseOneWire(t, at, 100, phaseOneHTTP("cmd=id"), false, false)})
			event, _ := s.Store.GetEvent(snap.EventID)
			source, err := s.collectPipelineInputs(ctx, event, snap)
			if err != nil {
				t.Fatal(err)
			}
			input, err := s.loadPipelinePrepared(ctx, source, false)
			if err != nil {
				t.Fatal(err)
			}
			seed, err := evaluateSnapshotFactInput(ctx, snap, input, nil, source.Options, source.Config)
			if err != nil || seed.Status != "evaluated" {
				t.Fatalf("seed invalid: %v %s", err, seed.Status)
			}
			// This is the previous release's storage address, used only to seed
			// an otherwise valid cached evaluation. Assertions exercise actual
			// Store lookup/load/warm reuse, not equality of key expressions.
			assets := append([]domain.Asset(nil), source.Assets...)
			sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
			o := source.Options
			oldParts := []any{temporalInputScopeVersion, PreparedEvidenceSchemaVersion, snap.EventID, snap.Version, snap.Watermark, snap.RevisionWatermark, evidence.RuleVersion, reportSnapshotAdapterVersion, source.Config, o, assets, o.Supplemental, o.SupplementalIssue, o.Sources, o.SourceIssue, o.RegistryIssue}
			if prior != "unversioned-result" {
				oldParts = append([]any{prior}, oldParts...)
			}
			oldKey := digest(oldParts)
			seed.InputDigest = "previous-preprocessing-sentinel"
			if err = putRecord(ctx, s.Store, "evidence_result", oldKey, snap.EventID, seed); err != nil {
				t.Fatal(err)
			}
			oldRecord, ok, err := s.Store.AggregateRecord(ctx, "evidence_result", oldKey)
			if err != nil || !ok {
				t.Fatal("seed not stored", err)
			}
			loads := 0
			load := func() (SnapshotEvidenceInput, error) { loads++; return s.loadPipelinePrepared(ctx, source, false) }
			cold, err := s.executePreparedPipeline(ctx, source, load, true, true, false)
			if err != nil || cold.Evaluation.CacheHit || loads != 1 || cold.Evaluation.InputDigest == seed.InputDigest {
				t.Fatalf("old cache reused or not recomputed: err=%v hit=%v loads=%d", err, cold.Evaluation.CacheHit, loads)
			}
			loads = 0
			warm, err := s.executePreparedPipeline(ctx, source, load, true, true, false)
			if err != nil || !warm.Evaluation.CacheHit || loads != 0 {
				t.Fatalf("control warm cache did not work: err=%v hit=%v loads=%d", err, warm.Evaluation.CacheHit, loads)
			}
			if cold.Evaluation.InputDigest != warm.Evaluation.InputDigest {
				t.Fatal("warm cache changed typed input identity")
			}
			unchanged, ok, err := s.Store.AggregateRecord(ctx, "evidence_result", oldKey)
			if err != nil || !ok || !bytes.Equal(oldRecord.Value, unchanged.Value) {
				t.Fatal("previous cache overwritten", err)
			}
			// Save a real revision with changed request bytes at the same event,
			// data version and hit membership. Its revision watermark alone must
			// select new inputs, while the older snapshot remains cacheable.
			changed := phaseOneWire(t, at, 100, phaseOneHTTP("cmd=cat"), false, false)
			raw, _ := json.Marshal(changed)
			rw, err := s.Store.InsertHitRevision(ctx, input.Request.Hits[0].ID, 2, raw)
			if err != nil {
				t.Fatal(err)
			}
			newSource := source
			newSource.Snapshot.RevisionWatermark = rw
			newLoads := 0
			loadNew := func() (SnapshotEvidenceInput, error) {
				newLoads++
				return s.loadPipelinePrepared(ctx, newSource, false)
			}
			revised, err := s.executePreparedPipeline(ctx, newSource, loadNew, true, true, false)
			if err != nil || revised.Evaluation.CacheHit || newLoads != 1 || revised.Evaluation.Manifest.RevisionWatermark != rw || revised.Evaluation.InputDigest == cold.Evaluation.InputDigest {
				t.Fatalf("revision reused old snapshot: err=%v hit=%v loads=%d watermark=%d", err, revised.Evaluation.CacheHit, newLoads, revised.Evaluation.Manifest.RevisionWatermark)
			}
			newLoads = 0
			revisedWarm, err := s.executePreparedPipeline(ctx, newSource, loadNew, true, true, false)
			if err != nil || !revisedWarm.Evaluation.CacheHit || newLoads != 0 || revisedWarm.Evaluation.InputDigest != revised.Evaluation.InputDigest {
				t.Fatal("revised snapshot warm cache invalid", err)
			}
			loads = 0
			oldWarm, err := s.executePreparedPipeline(ctx, source, load, true, true, false)
			if err != nil || !oldWarm.Evaluation.CacheHit || loads != 0 || oldWarm.Evaluation.InputDigest != cold.Evaluation.InputDigest || oldWarm.Evaluation.Manifest.RevisionWatermark != snap.RevisionWatermark {
				t.Fatal("new revision contaminated old snapshot", err)
			}
			t.Logf("prior=%s old_cache_bypassed=true cold_loads=1 warm_loads=0 revision_loads=1 old_snapshot_isolated=true", prior)
		})
	}
}

func TestProviderAssetSessionAggregationPreservesObservationIdentity(t *testing.T) {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	req := evidence.Request{Quality: evidence.Quality{Coverage: evidence.CoveragePartial}}
	for i, scope := range []evidence.Scope{
		{AssetID: "a", DeviceID: "d1", EndpointID: "tcp://192.0.2.1:443"},
		{AssetID: "a", DeviceID: "d1", EndpointID: "tcp://192.0.2.2:8443"},
		{AssetID: "a", DeviceID: "d2", EndpointID: "tcp://192.0.2.1:443"},
		{AssetID: "b", DeviceID: "d1", EndpointID: "tcp://192.0.2.1:443"},
	} {
		id := []string{"s1", "s2", "s3", "s4"}[i]
		session := evidence.Session{ID: id, SourceID: id + "-hit", Start: at, End: at.Add(time.Minute), UpBytes: uint64(100 + i), DownBytes: uint64(50 + i), HitIDs: []string{id + "-hit", id + "-other"}, ByteUnit: "wire", ObservationOnly: true}
		w := evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)}
		req.Inputs = append(req.Inputs, evidence.Input{Scope: scope, Window: &w, Network: &evidence.NetworkData{Provenance: evidence.Provenance{Verified: true, Complete: false, Version: "observed"}, Sessions: []evidence.Session{session}}})
	}
	original := digest(req.Inputs)
	buildSnapshotAssetInputs(&req)
	if len(req.AssetInputs) != 3 || digest(req.Inputs) != original {
		t.Fatal("asset/device isolation or source preservation failed")
	}
	for _, asset := range req.AssetInputs {
		var expected []evidence.Session
		for _, source := range req.Inputs {
			if source.Scope.AssetID == asset.Scope.AssetID && source.Scope.DeviceID == asset.Scope.DeviceID {
				expected = append(expected, source.Network.Sessions...)
			}
		}
		if asset.Scope.EndpointID != "asset://"+asset.Scope.AssetID || asset.Network.Complete || !reflect.DeepEqual(expected, asset.Network.Sessions) {
			t.Fatalf("session identity/counters/observational flags changed for %+v", asset.Scope)
		}
		if asset.Scope.AssetID == "a" && asset.Scope.DeviceID == "d1" {
			if len(asset.Network.Sessions) != 2 || asset.Network.Sessions[0].ID == asset.Network.Sessions[1].ID {
				t.Fatal("cross-endpoint sessions merged")
			}
			asset.Network.Sessions[0].HitIDs[0] = "mutated-aggregate"
			if req.Inputs[0].Network.Sessions[0].HitIDs[0] != "s1-hit" {
				t.Fatal("aggregate HitIDs alias source")
			}
			req.Inputs[1].Network.Sessions[0].HitIDs[0] = "mutated-source"
			if asset.Network.Sessions[1].HitIDs[0] != "s2-hit" {
				t.Fatal("source HitIDs alias aggregate")
			}
		}
	}
}

func TestProviderObservedSessionPreparedRoundTrip(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	snap := phaseOneInstallSnapshot(t, s, "session-prepared-roundtrip", 1, []map[string]any{phaseOneWire(t, at, 100, phaseOneHTTP("cmd=id"), false, false)})
	b, err := (EvidencePipeline{Services: s}).PrepareEvidenceBundle(context.Background(), snap.EventID)
	if err != nil {
		t.Fatal(err)
	}
	in := &b.Inputs.Request.Inputs[0]
	session := evidence.Session{ID: "observed-session", SourceID: b.Inputs.Request.Hits[0].ID, Start: at, End: at.Add(time.Second), UpBytes: 4096, DownBytes: 2048, HitIDs: []string{b.Inputs.Request.Hits[0].ID}, ByteUnit: "wire", ObservationOnly: true}
	in.Network.Sessions = []evidence.Session{session}
	// Snapshot membership completeness does not certify this observed session's
	// network window or volume; explicitly exercise a partial input family.
	in.Network.Complete = false
	b.Inputs.Request.Quality.Coverage = evidence.CoveragePartial
	b.Inputs.Request.AssetInputs = nil
	buildSnapshotAssetInputs(&b.Inputs.Request)
	b.Coverage = preparedFamilyCoverage(b.Inputs)
	b.Seal()
	var buf bytes.Buffer
	if err = EncodePreparedEvidence(&buf, b); err != nil {
		t.Fatal(err)
	}
	encoded := append([]byte(nil), buf.Bytes()...)
	decoded, err := DecodePreparedEvidence(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	for _, inputs := range [][]evidence.Input{decoded.Inputs.Request.Inputs, decoded.Inputs.Request.AssetInputs} {
		if len(inputs) != 1 || len(inputs[0].Network.Sessions) != 1 || !reflect.DeepEqual(inputs[0].Network.Sessions[0], session) {
			t.Fatal("prepared roundtrip lost source/session/counters/units/observation semantics")
		}
		if inputs[0].Network.Complete || inputs[0].Network.Sessions[0].VolumeVerified {
			t.Fatal("prepared roundtrip upgraded observational completeness")
		}
	}
	if !bytes.Contains(encoded, []byte(`"byte_unit":"wire"`)) || !bytes.Contains(encoded, []byte(`"observation_only":true`)) {
		t.Fatal("observational wire contract missing")
	}
	legacy, err := json.Marshal(evidence.Session{ID: "legacy"})
	if err != nil || strings.Contains(string(legacy), "byte_unit") || strings.Contains(string(legacy), "observation_only") {
		t.Fatal("optional metadata changes legacy/default wire shape")
	}
}

func TestProviderAssetSessionAggregationPreservesSourceAuthority(t *testing.T) {
	for _, tc := range []struct {
		name     string
		badIndex int
		verified bool
		complete bool
	}{
		{"global_complete_source_partial_first", 0, true, false},
		{"global_complete_source_partial_last", 1, true, false},
		{"source_unverified_first", 0, false, true},
		{"source_unverified_last", 1, false, true},
		{"all_sources_verified_complete_control", -1, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := evidence.Request{Quality: evidence.Quality{Coverage: evidence.CoverageComplete}}
			wantVerified, wantComplete := true, true
			for i, endpoint := range []string{"tcp://192.0.2.1:443", "tcp://192.0.2.2:8443"} {
				verified, complete := true, true
				if i == tc.badIndex {
					verified, complete = tc.verified, tc.complete
				}
				wantVerified = wantVerified && verified
				wantComplete = wantComplete && complete
				id := []string{"session-one", "session-two"}[i]
				req.Inputs = append(req.Inputs, evidence.Input{
					Scope: evidence.Scope{AssetID: "a", DeviceID: "d", EndpointID: endpoint},
					Network: &evidence.NetworkData{
						Provenance: evidence.Provenance{Verified: verified, Complete: complete, Version: "source-authority"},
						Sessions:   []evidence.Session{{ID: id, SourceID: id + "-hit", HitIDs: []string{id + "-hit"}}},
					},
				})
			}
			original := digest(req.Inputs)
			buildSnapshotAssetInputs(&req)
			if len(req.AssetInputs) != 1 || req.AssetInputs[0].Network == nil {
				t.Fatal("expected one asset/device network aggregate")
			}
			network := req.AssetInputs[0].Network
			if network.Complete != wantComplete {
				t.Errorf("network completeness upgraded from source: got=%v want=%v global=%s", network.Complete, wantComplete, req.Quality.Coverage)
			}
			if network.Verified != wantVerified {
				t.Errorf("network verification upgraded from source: got=%v want=%v", network.Verified, wantVerified)
			}
			if digest(req.Inputs) != original || len(network.Sessions) != 2 || network.Sessions[0].ID != "session-one" || network.Sessions[1].ID != "session-two" {
				t.Fatal("authority propagation changed sources or merged distinct sessions")
			}
		})
	}
}
