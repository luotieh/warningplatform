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
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Explicit opt-in: CI must not manufacture a real fixture when archives are absent.
func realChainIndependentArchive(t *testing.T) ([]store.Hit, []domain.Asset) {
	t.Helper()
	dir := os.Getenv("REAL_CHAIN_PARITY_ARCHIVE")
	if dir == "" {
		t.Skip("real saved-source replay requires REAL_CHAIN_PARITY_ARCHIVE")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "coverage180-raw-ly-14725b4b-84f0-4233-b6f3-98d6444ce2e6.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Data string `json:"gzip_base64"`
		SHA  string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	compressed, err := base64.StdEncoding.DecodeString(envelope.Data)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(io.LimitReader(z, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plain)
	actual := hex.EncodeToString(sum[:])
	if actual != envelope.SHA || actual != "466aaa3cdffbad11be8aaf203fa5df834657af426348d2414192e384e4b435e8" {
		t.Fatal("real source payload changed", actual)
	}
	var hits []store.Hit
	if err := json.Unmarshal(plain, &hits); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 874 {
		t.Fatal("real archive identity/count changed", len(hits))
	}
	inventory, err := os.ReadFile(filepath.Join(dir, "coverage180-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Assets []domain.Asset `json:"assets"`
	}
	if err := json.Unmarshal(inventory, &saved); err != nil {
		t.Fatal(err)
	}
	return hits, saved.Assets
}

func realChainIndependentAssemble(t *testing.T, hits []store.Hit, assets []domain.Asset) SnapshotEvidenceInput {
	t.Helper()
	start, end := hits[0].OccurredAt, hits[0].OccurredAt
	for _, h := range hits {
		if h.OccurredAt.Before(start) {
			start = h.OccurredAt
		}
		if h.OccurredAt.After(end) {
			end = h.OccurredAt
		}
	}
	// Source subset is deliberately not a complete 874-hit snapshot/window.
	snap := EvidenceSnapshot{EventID: hits[0].EventID, Version: 1, Watermark: 50000, RevisionWatermark: 200000, Count: 874, Sources: []string{hits[0].EventID}}
	out, _, _, err := assembleProviderTraffic(snap, assets, hits, evidence.AnalysisWindow{Start: start, End: end.Add(time.Nanosecond)})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range out.Request.Inputs {
		if in.HTTP != nil && in.HTTP.Complete {
			t.Fatal("complete individual exchange invented complete HTTP observation window")
		}
		if in.Network != nil && in.Network.Complete {
			t.Fatal("exchange invented complete network window")
		}
	}
	return out
}

func TestRealChainIndependentSavedHTTPResponse(t *testing.T) {
	hits, assets := realChainIndependentArchive(t)
	const source = "hit-26cc32d1d3941c95b764f7e75f3cc61a94dd979489db5919261df621dfa00991"
	var selected store.Hit
	for _, h := range hits {
		if h.ID == source {
			selected = h
			break
		}
	}
	if selected.ID == "" {
		t.Fatal("representative real source absent")
	}
	original := append([]byte(nil), selected.Raw...)
	out := realChainIndependentAssemble(t, []store.Hit{selected}, assets)
	var record *evidence.HTTPRecord
	for _, in := range out.Request.Inputs {
		if in.HTTP != nil {
			for _, r := range in.HTTP.Records {
				if r.SourceID == source {
					copy := r
					record = &copy
				}
			}
		}
	}
	if record == nil || !record.ResponseVerified || record.ResponseStatus != 200 {
		t.Fatalf("saved independently verifiable response did not reach HTTP record: %+v", record)
	}
	if record.TransactionID != "txn-9c6743a19705b67817b82b6fa6a689ad" || record.SessionID != "ses-263ad1fe79749b209545fd04e452c353" {
		t.Fatalf("real transaction identity lost: %+v", record)
	}
	matched := false
	for _, o := range out.SemanticObservations {
		if o.HitID == source && o.Complete && strings.Contains(o.Payload, "GET /aXz9q2w7e_nonexistent_path_probe HTTP/1.1") && strings.HasSuffix(o.Response, "ok\n") {
			matched = true
		}
	}
	if !matched {
		t.Fatal("verified response bytes did not reach same-source semantic observation")
	}
	if !bytes.Equal(original, selected.Raw) {
		t.Fatal("preprocessing mutated original source")
	}
	if len(out.Manifest.PhaseOne.CurrentContacts) != 1 {
		t.Fatalf("one verified real request must remain one independent contact: %d", len(out.Manifest.PhaseOne.CurrentContacts))
	}
	t.Log("real single saved transaction recovered; full snapshot, real model and segmented-response positives are not established by this subset")
}

func TestRealChainIndependentMissingRequestCannotBorrowNeighbor(t *testing.T) {
	hits, assets := realChainIndependentArchive(t)
	var positive store.Hit
	for _, h := range hits {
		if h.ID == "hit-26cc32d1d3941c95b764f7e75f3cc61a94dd979489db5919261df621dfa00991" {
			positive = h
		}
	}
	missing := []store.Hit{}
	for _, h := range hits {
		m := map[string]any{}
		if err := json.Unmarshal(h.Raw, &m); err != nil {
			t.Fatal(err)
		}
		ex := nestedMap(m, "exchange")
		packets, _ := nestedMap(ex, "response")["packets"].([]any)
		if len(packets) > 1 && asString(nestedMap(ex, "request")["reassembled_hex"]) == "" {
			missing = append(missing, h)
		}
	}
	if len(missing) != 88 {
		t.Fatal("real negative cohort identity changed", len(missing))
	}
	for _, negative := range missing {
		out := realChainIndependentAssemble(t, []store.Hit{positive, negative}, assets)
		for _, in := range out.Request.Inputs {
			if in.HTTP != nil {
				for _, r := range in.HTTP.Records {
					if r.SourceID == negative.ID && r.ResponseVerified {
						t.Fatal("requestless real response borrowed neighboring transaction", negative.ID)
					}
				}
			}
		}
		for _, o := range out.SemanticObservations {
			if o.HitID == negative.ID && o.Response != "" {
				t.Fatal("requestless source gained semantic response pair", negative.ID)
			}
		}
	}
	t.Log("all88 real requestless multi-packet-response sources remained unpaired beside one valid GET")
}

func TestRealChainIndependentHistoryBudgetCountsRetainedFields(t *testing.T) {
	const capBytes = 512
	reader := &remainingIndependentHistoryReader{rows: []domain.Event{{EventID: "oversized-non-context", Context: "{}", Title: strings.Repeat("large-title", 200), CreatedAt: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)}}}
	rows, _, err := providerCandidatesWithinBytes(context.Background(), reader, store.HistoryQuery{SummaryOnly: true}, 4, capBytes)
	if err != nil {
		t.Fatal(err)
	}
	retained := 0
	for _, row := range rows {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		retained += len(raw)
	}
	if retained > capBytes {
		t.Fatalf("budget counted Context only: retained full summaries=%d exceeds cap=%d", retained, capBytes)
	}
	if reader.calls != 1 {
		t.Fatal("byte accounting issued extra per-event reads", reader.calls)
	}
}

func realChainIndependentSubjects(t *testing.T) SnapshotEvidenceInput {
	t.Helper()
	at := time.Date(2026, 10, 21, 4, 0, 0, 0, time.UTC)
	scope := evidence.Scope{AssetID: "owner", DeviceID: "device", EndpointID: "tcp://203.0.113.8:80"}
	out := SnapshotEvidenceInput{Request: evidence.Request{EventID: "current", SnapshotVersion: 1, Facts: []evidence.FactID{"F_HIST_INFRA_PERSISTENCE"}, Quality: evidence.Quality{Coverage: evidence.CoveragePartial}}, Manifest: SnapshotEvidenceManifest{PhaseOne: &PhaseOneMaterials{}}}
	in := evidence.Input{Scope: scope, Window: &evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)}}
	for n, kind := range []string{"ip", "domain", "url"} {
		value := []string{"203.0.113.8", "same-text.example", "http://same-text.example/a"}[n]
		id := "current-" + kind
		out.Request.Hits = append(out.Request.Hits, evidence.Hit{ID: id, Scope: scope, OccurredAt: at.Add(time.Duration(n) * time.Minute)})
		out.Manifest.PhaseOne.CurrentBindings = append(out.Manifest.PhaseOne.CurrentBindings, evidence.PhaseOneBinding{Scope: scope, IOCType: kind, IOCValue: value, SourceID: id, Verified: true, Field: "independent-test-source"})
		h := &evidence.HistoryData{IOC: value, PlatformRecords: true, AsOf: at, LookbackStart: at.AddDate(0, 0, -30), Provenance: evidence.Provenance{Verified: true, Complete: false, Version: "saved-summary-v1", SourceIDs: []string{"history-proof-" + kind}}}
		// Distinct outcomes force normalization to match the exact execution,
		// rather than letting the first same-Scope execution label every IOC.
		if kind == "domain" {
			h.Verified = false
		}
		// IP is independently positive; URL has a genuine partial gap.
		if n == 0 {
			for day := 1; day <= 2; day++ {
				h.Events = append(h.Events, evidence.HistoryEvent{ID: []string{"history-ip-A", "history-ip-B"}[day-1], Time: at.AddDate(0, 0, -day), AssetID: []string{"asset-A", "asset-B"}[day-1], IOCType: kind, IOC: value})
			}
		}
		in.PlatformHistorySubjects = append(in.PlatformHistorySubjects, evidence.HistorySubject{IOCType: kind, IOCValue: value, CurrentSourceIDs: []string{id}, History: h})
	}
	// Must not create an additional untyped legacy execution.
	in.PlatformHistory = in.PlatformHistorySubjects[0].History
	out.Request.Inputs = []evidence.Input{in}
	return out
}

func TestRealChainIndependentSubjectsRoundTripAndNormalization(t *testing.T) {
	out := realChainIndependentSubjects(t)
	wire := capturePreparedInputs(out)
	if err := validatePreparedHistorySubjects(wire); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"platform_history_subjects"`)) {
		t.Fatal("private subjects were not persisted at actual wire path")
	}
	var decoded EvidencePreparedInputs
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validatePreparedHistorySubjects(decoded); err != nil {
		t.Fatal(err)
	}
	restored := restorePreparedInputs(decoded)
	engine, err := evidence.NewEngine(evidence.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Evaluate(context.Background(), restored.Request)
	if err != nil {
		t.Fatal(err)
	}
	infraExecutions := 0
	for _, execution := range result.Executions {
		if execution.FactID == "F_HIST_INFRA_PERSISTENCE" {
			infraExecutions++
		}
	}
	if len(result.Findings) != 3 || infraExecutions != 3 {
		t.Fatal("subjects collapsed or legacy branch executed twice", len(result.Findings), infraExecutions)
	}
	normalized := evidence.Normalize(result.Findings, nil, result.Executions)
	seen := map[string]bool{}
	for _, item := range normalized.Items {
		if item.RuleID != "F_HIST_INFRA_PERSISTENCE" {
			continue
		}
		if seen[item.ID] {
			t.Fatal("distinct IOC normalized identity merged", item.IOCType, item.IOCValue)
		}
		seen[item.ID] = true
		if item.IOCType == "ip" && item.Status != "observed" {
			t.Fatal("positive IP changed", item)
		}
		if item.IOCType == "url" && (item.Status != "missing" || item.Reason != "incomplete_coverage_cannot_refute") {
			t.Fatal("partial IOC inherited another subject status", item)
		}
		if item.IOCType == "domain" && (item.Status != "missing" || item.Reason != "missing_input") {
			t.Fatal("unverified history inherited another subject outcome", item)
		}
		if !slices.Contains(item.SourceIDs, "current-"+item.IOCType) {
			t.Fatal("subject lost own current source", item)
		}
		for _, other := range []string{"ip", "domain", "url"} {
			if other != item.IOCType && slices.Contains(item.SourceIDs, "current-"+other) {
				t.Fatal("cross-subject current SourceIDs contamination", item)
			}
			if other != item.IOCType && slices.Contains(item.SourceIDs, "history-proof-"+other) {
				t.Fatal("cross-subject historical SourceIDs contamination", item)
			}
		}
		wantExecution := "executed"
		if item.IOCType == "domain" {
			wantExecution = "skipped"
		}
		if item.ExecutionStatus != wantExecution {
			t.Fatal("execution identity did not match its finding", item)
		}
	}
	if len(seen) != 3 {
		t.Fatal("normalization lost subjects", len(seen))
	}
}

func TestRealChainIndependentSubjectsRejectUnboundPreparedSources(t *testing.T) {
	for _, kind := range []string{"other-subject-source", "foreign-scope", "history-as-current", "wrong-row-type", "duplicate-subject", "unknown-scope"} {
		t.Run(kind, func(t *testing.T) {
			out := realChainIndependentSubjects(t)
			wire := capturePreparedInputs(out)
			key := scopeKey(out.Request.Inputs[0].Scope)
			s := wire.PlatformHistorySubjects[key]
			switch kind {
			case "other-subject-source":
				s[1].CurrentSourceIDs = []string{"current-ip"}
			case "foreign-scope":
				wire.Request.Hits[1].Scope.DeviceID = "foreign-device"
			case "history-as-current":
				s[1].CurrentSourceIDs = []string{"history-ip-A"}
			case "wrong-row-type":
				s[0].History.Events[0].IOCType = "domain"
			case "duplicate-subject":
				s = append(s, s[0])
			case "unknown-scope":
				wire.PlatformHistorySubjects["unknown"] = s
			}
			wire.PlatformHistorySubjects[key] = s
			if err := validatePreparedHistorySubjects(wire); err == nil {
				t.Fatal("unbound prepared subject accepted", kind)
			}
		})
	}
}

// This goes through the shared report/prepared execution pipeline, whose
// independent-fact merge rebuilds Executions after Engine.Evaluate. Engine-only
// assertions cannot detect a lost identity or changed execution at that join.
func TestRealChainIndependentSubjectsSurvivePipelineJoin(t *testing.T) {
	in := realChainIndependentSubjects(t)
	in.Request.Facts = evidence.SupportedFacts()
	in.Manifest.PhaseOne.Expanded = true
	snap := EvidenceSnapshot{EventID: in.Request.EventID, Version: in.Request.SnapshotVersion, Context: map[string]any{}}
	opts := DefaultSnapshotEvidenceOptions()
	opts.Facts, opts.DeferIndependentFacts = evidence.SupportedFacts(), true
	opts.ReportMaterialMode, opts.CaptureSemantic = true, true
	source := pipelinePreparedSource{Event: domain.Event{EventID: snap.EventID, Context: "{}"}, Snapshot: snap, Options: opts, Config: evidence.DefaultConfig()}
	out, err := (Services{}).executePreparedPipeline(context.Background(), source, func() (SnapshotEvidenceInput, error) { return in, nil }, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, item := range out.Evidence.Normalized.Items {
		if item.RuleID != "F_HIST_INFRA_PERSISTENCE" {
			continue
		}
		if seen[item.IOCType] || item.IOCValue == "" || item.ObservationKind != "event_occurrence" {
			t.Fatal("pipeline join collapsed or erased subject identity", item)
		}
		seen[item.IOCType] = true
		want := "executed"
		if item.IOCType == "domain" {
			want = "skipped"
		}
		if item.ExecutionStatus != want {
			t.Fatal("pipeline join changed exact engine execution", item)
		}
		if !slices.Contains(item.SourceIDs, "current-"+item.IOCType) {
			t.Fatal("pipeline join lost current subject source", item)
		}
		for _, other := range []string{"ip", "domain", "url"} {
			if other != item.IOCType && slices.Contains(item.SourceIDs, "current-"+other) {
				t.Fatal("pipeline join mixed current subject sources", item)
			}
		}
	}
	if len(seen) != 3 {
		t.Fatal("pipeline join did not retain all three subjects", seen)
	}
}
