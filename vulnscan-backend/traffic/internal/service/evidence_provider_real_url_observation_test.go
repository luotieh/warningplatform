package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

func TestProviderURLObservationRequiresVerifiedWireBytes(t *testing.T) {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	payload := "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"
	m := map[string]any{"session_id": "session", "transaction_id": "transaction", "device_id": "node", "src_ip": "192.0.2.1", "dst_ip": "203.0.113.1", "src_port": 45000, "dst_port": 80, "protocol": "tcp", "raw_packet": map[string]any{"payload_hex": hex.EncodeToString([]byte(payload)), "capture_truncated": false}}
	input := evidence.Input{Scope: evidence.Scope{AssetID: "asset", DeviceID: "node", EndpointID: "tcp://203.0.113.1:80"}, Window: &evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)}}
	manifest := SnapshotEvidenceManifest{}
	enrichSnapshotProtocols(&input, store.Hit{ID: "payload-only", OccurredAt: at}, m, &manifest)
	if input.HTTP == nil || len(input.HTTP.Records) != 1 || input.HTTP.Records[0].Truncated || input.HTTP.Records[0].RequestVerification != nil {
		t.Fatal("payload-only full claim acquired verified wire request authority")
	}
}

func TestProviderRealURLObservationArchived874(t *testing.T) {
	dir := os.Getenv("REAL_CHAIN_PARITY_ARCHIVE")
	if dir == "" {
		t.Skip("requires immutable original frozen collection")
	}
	path := filepath.Join(dir, "real-chain-parity", "20261021-execution", "fixtures", "archived-http", "ly-14725b4b-84f0-4233-b6f3-98d6444ce2e6", "platform-collection.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "8b154ea86a6f422dce3f81487cf857d8e78ab19ebd2dcf206a46e254ff939343" {
		t.Fatal("frozen source changed")
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
		t.Fatal("frozen collection mutated")
	}
	// Public Bundle JSON roundtrip, not its in-memory RawRequest side channel.
	var encoded bytes.Buffer
	if err = EncodePreparedEvidence(&encoded, bundle); err != nil {
		t.Fatal(err)
	}
	restored, err := DecodePreparedEvidence(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	public, err := ExecutePreparedEvidence(context.Background(), restored, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal("public prepared execution failed", err)
	}
	publicMatched := false
	for _, n := range public.Evidence.Normalized.Items {
		if n.RuleID == "F_URL_ODD_AUTHORITY" && n.ObservationKind == "complete_http_request" && n.ExecutionStatus == "executed" && n.Status == "not_observed" && n.Measurements != nil && n.Measurements.SampleCount == 117 {
			publicMatched = true
		}
	}
	if !publicMatched {
		t.Fatal("public pipeline dropped typed subset finding or execution")
	}
	if dir := os.Getenv("URL_OBSERVATION_ARTIFACT_DIR"); dir != "" {
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		result, err := json.Marshal(public)
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{"prepared-bundle.json": encoded.Bytes(), "execution.json": result} {
			f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.Write(data)
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
		}
		t.Logf("public_encode_decode_execute=true normalized_execution=executed semantic_mode=disabled artifacts=%s", dir)
	}
	input := restorePreparedInputs(restored.Inputs)
	input.Request.Facts = []evidence.FactID{"F_URL_ODD_AUTHORITY"}
	engine, _ := evidence.NewEngine(evidence.DefaultConfig())
	after, err := engine.Evaluate(context.Background(), input.Request)
	if err != nil {
		t.Fatal(err)
	}
	normalized := evidence.Normalize(after.Findings, nil, after.Executions)
	verified, rows, familyComplete := 0, 0, false
	for _, i := range input.Request.Inputs {
		if i.HTTP == nil {
			continue
		}
		rows += len(i.HTTP.Records)
		familyComplete = familyComplete || i.HTTP.Complete
		for _, r := range i.HTTP.Records {
			if r.RequestVerification != nil {
				verified++
			}
		}
	}
	found := 0
	for _, f := range after.Findings {
		if f.ObservationKind != "complete_http_request" {
			continue
		}
		found++
		if f.Status != evidence.NotObserved || f.Eligibility != "eligible" || f.Measurements.SampleCount != 117 || f.Measurements.Values["odd_authority_count"] != 0 || f.Measurements.Values["conflicting_request_groups"] != 51 || len(f.SourceIDs) == 0 {
			t.Fatal("real subset calculation changed", f)
		}
		matched := false
		for _, n := range normalized.Items {
			if n.RuleID == string(f.FactID) && n.Scope == f.Scope && n.ObservationKind == f.ObservationKind && n.ExecutionStatus == "executed" {
				matched = true
			}
		}
		if !matched {
			t.Fatal("normalized execution identity lost")
		}
		t.Logf("real=true event=%s projections=%d verified=%d unique_request_samples=%d conflicting_groups=%v excluded_projections=%v retained_source_refs=%d odd_authority=%v status=%s family_complete=%t public_bundle_roundtrip=true", c.Snapshot.EventID, rows, verified, f.Measurements.SampleCount, f.Measurements.Values["conflicting_request_groups"], f.Measurements.Values["excluded_request_projections"], len(f.SourceIDs), f.Measurements.Values["odd_authority_count"], f.Status, familyComplete)
	}
	if found != 1 || rows != 376 || verified != 376 || familyComplete {
		t.Fatal("unexpected real coverage", found, rows, verified, familyComplete)
	}
	// Exact same source data without the new parsed-byte verification contract
	// reproduces the original missing gate; no new collection or external data.
	for idx := range input.Request.Inputs {
		if h := input.Request.Inputs[idx].HTTP; h != nil {
			for j := range h.Records {
				h.Records[j].RequestVerification = nil
			}
		}
	}
	old, err := engine.Evaluate(context.Background(), input.Request)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range old.Findings {
		if f.Status != evidence.Missing {
			t.Fatal("unmarked partial input became authority", f)
		}
	}
}
