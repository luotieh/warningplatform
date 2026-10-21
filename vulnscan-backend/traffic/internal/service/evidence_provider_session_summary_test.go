package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func providerSessionTestRow(t *testing.T, id string, first time.Time, second int, counts [5]uint64) store.Hit {
	t.Helper()
	at := first.Add(time.Duration(second) * time.Second)
	m := phaseOneWire(t, at, uint32(second+1), nil, false, true)
	m["session_summary"] = map[string]any{"first_time_usec": first.UnixMicro(), "last_time_usec": at.UnixMicro(), "client_packets": counts[0], "server_packets": counts[1], "client_wire_bytes": counts[2], "server_wire_bytes": counts[3], "hit_count": counts[4]}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return store.Hit{ID: id, EventID: "summary-fixture", OccurredAt: at, Raw: raw}
}

func providerSessionChange(t *testing.T, h store.Hit, mutate func(map[string]any)) store.Hit {
	t.Helper()
	m := map[string]any{}
	d := json.NewDecoder(bytes.NewReader(h.Raw))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	h.Raw = raw
	return h
}

func providerSessionAssemble(t *testing.T, hs []store.Hit, assets []domain.Asset, w evidence.AnalysisWindow) SnapshotEvidenceInput {
	t.Helper()
	out, _, _, err := assembleProviderTraffic(EvidenceSnapshot{EventID: hs[0].EventID, Version: 1}, assets, hs, w)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func providerSessionRecords(out SnapshotEvidenceInput) []evidence.Session {
	var sessions []evidence.Session
	for _, in := range out.Request.Inputs {
		if in.Network != nil {
			sessions = append(sessions, in.Network.Sessions...)
		}
	}
	return sessions
}

func TestProviderObservedSessionWholeRowAndAuthority(t *testing.T) {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	hs := []store.Hit{providerSessionTestRow(t, "h1", at, 0, [5]uint64{1, 0, 74, 0, 1}), providerSessionTestRow(t, "h2", at, 2, [5]uint64{2, 1, 148, 54, 2}), providerSessionTestRow(t, "h3", at, 2, [5]uint64{2, 1, 148, 54, 3})}
	assets := []domain.Asset{{ID: "a", Address: "192.0.2.1", Status: 1}}
	w := evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)}
	out := providerSessionAssemble(t, hs, assets, w)
	sessions := providerSessionRecords(out)
	if len(sessions) != 1 {
		t.Fatal("cumulative hits became individual sessions", sessions, out.Manifest.Issues)
	}
	s := sessions[0]
	if s.SourceID != "h3" || s.UpBytes != 148 || s.DownBytes != 54 || s.VolumeVerified || s.ByteUnit != "wire" || !s.ObservationOnly || len(s.HitIDs) != 3 || !s.Start.Equal(at) || !s.End.Equal(at.Add(2*time.Second)) {
		t.Fatal("original whole summary changed", s)
	}
	if out.Request.Quality.Coverage != evidence.CoveragePartial || out.Request.Inputs[0].Network.Complete {
		t.Fatal("summary invented coverage")
	}
	buildProviderAssetInputs(&out.Request)
	if len(out.Request.AssetInputs) != 1 || len(out.Request.AssetInputs[0].Network.Sessions) != 1 {
		t.Fatal("asset aggregation lost sessions", out.Request.AssetInputs)
	}
	out.Request.AssetInputs[0].Network.Sessions[0].HitIDs[0] = "mutated"
	if out.Request.Inputs[0].Network.Sessions[0].HitIDs[0] == "mutated" {
		t.Fatal("asset session HitIDs alias endpoint")
	}
	// Accumulator itself is per-assembly, not a reusable/apply-twice service.
	reversed := slices.Clone(hs)
	slices.Reverse(reversed)
	other := providerSessionAssemble(t, reversed, assets, w)
	if digest(providerSessionRecords(other)) != digest(sessions) {
		t.Fatal("input order changed selected summary")
	}
	for _, elevateVolume := range []bool{false, true} {
		req := other.Request
		req.Facts = []evidence.FactID{"F_LONG_LOW_SESSION"}
		req.Quality.Coverage = evidence.CoverageComplete
		req.Inputs[0].Network.Complete = true
		req.Inputs[0].Network.Sessions[0].VolumeVerified = elevateVolume
		engine, _ := evidence.NewEngine(evidence.DefaultConfig())
		result, err := engine.Evaluate(context.Background(), req)
		if err != nil || len(result.Findings) != 1 || result.Findings[0].Status != evidence.Missing || result.Findings[0].ReasonCode != evidence.MissingInput {
			t.Fatal("observation-only record became algorithm authority", elevateVolume, result, err)
		}
	}
}

func TestProviderObservedSessionRejectUnsafeSummaries(t *testing.T) {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	assets := []domain.Asset{{ID: "a", Address: "192.0.2.1", Status: 1}}
	base := providerSessionTestRow(t, "h1", at, 0, [5]uint64{2, 1, 148, 54, 2})
	later := providerSessionTestRow(t, "h2", at, 2, [5]uint64{3, 2, 222, 108, 3})
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"counter_regression", func(m map[string]any) { nestedMap(m, "session_summary")["client_wire_bytes"] = 100 }},
		{"incomparable_vector", func(m map[string]any) {
			s := nestedMap(m, "session_summary")
			s["client_packets"] = 1
		}},
		{"first_changed", func(m map[string]any) {
			nestedMap(m, "session_summary")["first_time_usec"] = at.Add(time.Second).UnixMicro()
		}},
		{"local_port_collision", func(m map[string]any) { m["src_port"] = 45001 }},
		{"endpoint_collision", func(m map[string]any) { m["dst_port"] = 81 }},
		{"counter_overflow", func(m map[string]any) { nestedMap(m, "session_summary")["client_wire_bytes"] = "18446744073709551616" }},
		{"negative", func(m map[string]any) { nestedMap(m, "session_summary")["client_packets"] = -1 }},
		{"float", func(m map[string]any) { nestedMap(m, "session_summary")["client_packets"] = 1.5 }},
		{"time_overflow", func(m map[string]any) { nestedMap(m, "session_summary")["last_time_usec"] = "18446744073709551615" }},
		{"summary_excludes_occurrence", func(m map[string]any) {
			nestedMap(m, "session_summary")["last_time_usec"] = at.Add(time.Second).UnixMicro()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := providerSessionChange(t, later, tc.change)
			out := providerSessionAssemble(t, []store.Hit{base, changed}, assets, evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)})
			if len(providerSessionRecords(out)) != 0 {
				t.Fatal("unsafe summary got a session", providerSessionRecords(out))
			}
			if out.Manifest.IssueCount == 0 {
				t.Fatal("rejected summary lacked bounded diagnostics")
			}
		})
	}
	// A SYN from one device must never supply the other device's missing role.
	unknown := providerSessionTestRow(t, "unknown", at, 2, [5]uint64{3, 2, 222, 108, 3})
	unknown = providerSessionChange(t, unknown, func(m map[string]any) { m["device_id"] = "node-b"; delete(m, "raw_packet"); delete(m, "exchange") })
	out := providerSessionAssemble(t, []store.Hit{base, unknown}, assets, evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)})
	if got := providerSessionRecords(out); len(got) != 1 || got[0].SourceID != "h1" {
		t.Fatal("cross-device role borrowing", got)
	}
	// A duplicate source ID with different snapshots cannot manufacture a join.
	later.ID = base.ID
	if got := providerSessionRecords(providerSessionAssemble(t, []store.Hit{base, later}, assets, evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)})); len(got) != 0 {
		t.Fatal("conflicting duplicate source accepted", got)
	}
}

func TestProviderObservedSessionReportedSpanKeepsEventWindow(t *testing.T) {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	assets := []domain.Asset{{ID: "a", Address: "192.0.2.1", Status: 1}}
	w := evidence.AnalysisWindow{Start: at, End: at.Add(time.Nanosecond)}
	h := providerSessionTestRow(t, "trigger", at, 0, [5]uint64{2, 1, 148, 54, 1})
	h = providerSessionChange(t, h, func(m map[string]any) {
		nestedMap(m, "session_summary")["last_time_usec"] = at.Add(2 * time.Hour).UnixMicro()
	})
	out := providerSessionAssemble(t, []store.Hit{h}, assets, w)
	s := providerSessionRecords(out)
	if len(s) != 1 || !s[0].End.Equal(at.Add(2*time.Hour)) || s[0].VolumeVerified || !s[0].ObservationOnly || s[0].ByteUnit != "wire" {
		t.Fatal("reported span lost or granted session authority", s, out.Manifest.Issues)
	}
	if *out.Request.Inputs[0].Window != w || !out.Request.Hits[0].OccurredAt.Equal(at) || len(out.Manifest.PhaseOne.Contacts) != 1 || !out.Manifest.PhaseOne.Contacts[0].Time.Equal(at) {
		t.Fatal("summary revision moved occurrence/window/contact time")
	}
	outsideDiagnostic := false
	for _, issue := range out.Manifest.Issues {
		outsideDiagnostic = outsideDiagnostic || issue.Code == "session_summary_observation_span_outside_event_window"
	}
	if !outsideDiagnostic {
		t.Fatal("reported span outside event window lacks diagnostic")
	}
	// A source outside the selected event window still cannot enter, even when
	// its self-reported summary contains the source occurrence.
	outside := providerSessionTestRow(t, "outside", at, 2, [5]uint64{2, 1, 148, 54, 1})
	if got := providerSessionRecords(providerSessionAssemble(t, []store.Hit{outside}, assets, w)); len(got) != 0 {
		t.Fatal("out-of-window source accepted", got)
	}
	// Nor may a reported observation window exclude its immutable occurrence.
	excludes := providerSessionChange(t, h, func(m map[string]any) {
		nestedMap(m, "session_summary")["first_time_usec"] = at.Add(time.Second).UnixMicro()
	})
	if got := providerSessionRecords(providerSessionAssemble(t, []store.Hit{excludes}, assets, w)); len(got) != 0 {
		t.Fatal("reported span excludes original occurrence", got)
	}
	// An older reported start is retained as a claim too, never as a new event.
	early := providerSessionChange(t, h, func(m map[string]any) {
		nestedMap(m, "session_summary")["first_time_usec"] = at.Add(-time.Second).UnixMicro()
	})
	earlyOut := providerSessionAssemble(t, []store.Hit{early}, assets, w)
	if got := providerSessionRecords(earlyOut); len(got) != 1 || !got[0].Start.Equal(at.Add(-time.Second)) || *earlyOut.Request.Inputs[0].Window != w {
		t.Fatal("reported start altered event window", got)
	}
}

func TestProviderObservedSessionServerAssetAndRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	h := providerSessionTestRow(t, "h", at, 2, [5]uint64{3, 2, 222, 108, 3})
	out := providerSessionAssemble(t, []store.Hit{h}, []domain.Asset{{ID: "server", Address: "203.0.113.2", Status: 1}}, evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)})
	s := providerSessionRecords(out)
	if len(s) != 1 || s[0].UpBytes != 108 || s[0].DownBytes != 222 {
		t.Fatal("client wire counters not oriented to actual asset", s)
	}
	before := capturePreparedInputs(out)
	raw, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	var decoded EvidencePreparedInputs
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	restored := restorePreparedInputs(decoded)
	if digest(providerSessionRecords(restored)) != digest(s) {
		t.Fatal("wire/observation metadata lost through serialization")
	}
	d1 := digest(before.Request)
	restored.Request.Inputs[0].Network.Sessions[0].UpBytes++
	if d1 == digest(restored.Request) {
		t.Fatal("session bytes do not bind actual input identity")
	}
}

func TestProviderObservedSessionRealArchive(t *testing.T) {
	dir := os.Getenv("REAL_CHAIN_PARITY_ARCHIVE")
	if dir == "" {
		t.Skip("requires frozen real archive, never replace with fixture")
	}
	envelope, err := os.ReadFile(filepath.Join(dir, "coverage180-raw-ly-14725b4b-84f0-4233-b6f3-98d6444ce2e6.json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Data string `json:"gzip_base64"`
		SHA  string `json:"sha256"`
	}
	if err = json.Unmarshal(envelope, &env); err != nil {
		t.Fatal(err)
	}
	compressed, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(z, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != env.SHA || env.SHA != "466aaa3cdffbad11be8aaf203fa5df834657af426348d2414192e384e4b435e8" {
		t.Fatal("real saved archive SHA changed")
	}
	var hs []store.Hit
	if err = json.Unmarshal(raw, &hs); err != nil {
		t.Fatal(err)
	}
	inv, err := os.ReadFile(filepath.Join(dir, "coverage180-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Assets []domain.Asset `json:"assets"`
	}
	if err = json.Unmarshal(inv, &inventory); err != nil {
		t.Fatal(err)
	}
	if len(hs) != 874 {
		t.Fatal("saved original hit count changed", len(hs))
	}
	start, end := hs[0].OccurredAt, hs[0].OccurredAt
	for _, h := range hs {
		if h.OccurredAt.Before(start) {
			start = h.OccurredAt
		}
		if h.OccurredAt.After(end) {
			end = h.OccurredAt
		}
	}
	out := providerSessionAssemble(t, hs, inventory.Assets, evidence.AnalysisWindow{Start: start, End: end.Add(time.Nanosecond)})
	sessions := providerSessionRecords(out)
	if len(sessions) == 0 || len(sessions) >= len(hs) {
		t.Fatal("real cumulative summaries still absent or inflated into per-hit sessions", len(sessions))
	}
	matched := false
	for _, s := range sessions {
		if !s.ObservationOnly || s.ByteUnit != "wire" || s.VolumeVerified {
			t.Fatal("real observation granted volume authority", s)
		}
		if s.ID == "ses-d3b371fac946e753ce37408fe7236368" {
			matched = true
			if s.UpBytes != 34489 || s.DownBytes != 20606 || len(s.HitIDs) != 274 {
				t.Fatal("largest saved summary did not preserve original selected row", s)
			}
		}
	}
	if !matched {
		t.Fatal("documented valid largest observation was lost", out.Manifest.Issues)
	}
	buildProviderAssetInputs(&out.Request)
	assetSessions := 0
	for _, in := range out.Request.AssetInputs {
		if in.Network != nil {
			assetSessions += len(in.Network.Sessions)
			if in.Network.Complete {
				t.Fatal("real session invented asset network coverage")
			}
		}
	}
	if assetSessions != len(sessions) {
		t.Fatal("asset aggregation lost existing real observations", len(sessions), assetSessions)
	}
	out.Request.Facts = []evidence.FactID{"F_LONG_LOW_SESSION"}
	engine, _ := evidence.NewEngine(evidence.DefaultConfig())
	result, err := engine.Evaluate(context.Background(), out.Request)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.Status != evidence.Missing || f.ReasonCode != evidence.UnverifiedCoverage {
			t.Fatal("real short observed segments unlocked long session algorithm", f)
		}
	}
	t.Logf("real_summary_consumer archive_hits=%d observed_sessions=%d asset_sessions=%d retained_wire=true volume_verified=false full_session=false long_session=missing_unverified_coverage issues=%d", len(hs), len(sessions), assetSessions, out.Manifest.IssueCount)
}

func TestProviderObservedSessionFrozenCollections(t *testing.T) {
	dir := os.Getenv("REAL_CHAIN_PARITY_ARCHIVE")
	if dir == "" {
		t.Skip("requires original frozen collections")
	}
	root := filepath.Join(dir, "real-chain-parity", "20261021-execution", "fixtures")
	for _, tc := range []struct{ path, sha string }{
		{"ly-17a185a3-79b8-48fe-bb18-612b81c31a86", "1433b260ace3b6c9f74be1fa16051915a8d5de10556192fd63811e04de953fe6"},
		{"ly-9b6c454d-ebf1-466a-9fbd-732ec2c032e3", "bf904283d6316ef2b6775e3d1d5af9c58abe58d4fc014823e114761c39c98a2c"},
		{"ly-ebab72a6-1856-4ff7-8e29-e327cae097fd", "550d9ba0be698eb009f963f65381ea537ce8f0e2c5732a6571970222cf7cbd83"},
		{filepath.Join("archived-http", "ly-14725b4b-84f0-4233-b6f3-98d6444ce2e6"), "8b154ea86a6f422dce3f81487cf857d8e78ab19ebd2dcf206a46e254ff939343"},
		{filepath.Join("archived-http", "ly-fd1496c4-14e6-40ae-bb29-57d162a9d94f"), "7be75be3e7e4fd64c3a4ef9527e7ee2865d0f78f3bb6229a936613e90e79e376"},
	} {
		t.Run(filepath.Base(tc.path), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, tc.path, "platform-collection.json"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != tc.sha {
				t.Fatal("immutable original collection changed")
			}
			var c EvidenceCollection
			if err = json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			before := digest(c)
			bundle, _, err := PreprocessCollectedEvidence(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			if digest(c) != before {
				t.Fatal("session adapter mutated frozen raw collection")
			}
			out := restorePreparedInputs(bundle.Inputs)
			sessions := providerSessionRecords(out)
			for _, s := range sessions {
				if !s.ObservationOnly || s.ByteUnit != "wire" || s.VolumeVerified {
					t.Fatal("observed session authority upgraded", s)
				}
			}
			out.Request.Facts = []evidence.FactID{"F_LONG_LOW_SESSION"}
			engine, _ := evidence.NewEngine(evidence.DefaultConfig())
			r, err := engine.Evaluate(context.Background(), out.Request)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range r.Findings {
				if f.Status != evidence.Missing {
					t.Fatal("summary presence made real long session executable", f)
				}
			}
			t.Logf("frozen_collection event=%s hits=%d observed_sessions=%d full_session=false long_session=missing raw_immutable=true", c.Snapshot.EventID, len(c.Hits), len(sessions))
		})
	}
}
