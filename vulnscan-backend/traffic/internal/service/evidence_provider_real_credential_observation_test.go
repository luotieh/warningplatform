package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

func TestProviderCredentialObservationParsedFields(t *testing.T) {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, media, body string
		verified          bool
		status            evidence.Status
	}{
		{"complete_form_POST", "application/x-www-form-urlencoded", "username=synthetic&password=synthetic", true, evidence.Observed},
		{"opaque_text_POST", "text/plain", "password=synthetic", false, evidence.Missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(fmt.Sprintf("POST /login HTTP/1.1\r\nHost: example.org\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", tc.media, len(tc.body), tc.body))
			m := phaseOneWire(t, at, 100, payload, false, false)
			scope := evidence.Scope{AssetID: "asset", DeviceID: "node-a", EndpointID: "tcp://203.0.113.2:80"}
			input := evidence.Input{Scope: scope, Window: &evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)}}
			manifest := SnapshotEvidenceManifest{}
			enrichSnapshotProtocols(&input, store.Hit{ID: "post", OccurredAt: at}, m, &manifest)
			if input.HTTP == nil || len(input.HTTP.Records) != 1 {
				t.Fatal("request projection unavailable")
			}
			r := input.HTTP.Records[0]
			if r.RequestVerification == nil || r.RequestVerification.FieldsVerified != tc.verified {
				t.Fatal("parsed byte field authority incorrect", r.RequestVerification)
			}
			input.HTTP.Provenance = evidence.Provenance{Verified: true, Complete: false, Version: "synthetic-wire:1", SourceIDs: []string{"post"}}
			request := evidence.Request{EventID: "synthetic-post", SnapshotVersion: 1, Facts: []evidence.FactID{"F_CRED_POST_STRUCTURE"}, Quality: evidence.Quality{Coverage: evidence.CoveragePartial}, Inputs: []evidence.Input{input}, Hits: []evidence.Hit{{ID: "post", Scope: scope, OccurredAt: at}}}
			wire, _ := json.Marshal(request)
			var restored evidence.Request
			if err := json.Unmarshal(wire, &restored); err != nil {
				t.Fatal(err)
			}
			engine, _ := evidence.NewEngine(evidence.DefaultConfig())
			result, err := engine.Evaluate(context.Background(), restored)
			if err != nil || len(result.Findings) != 1 || result.Findings[0].Status != tc.status {
				t.Fatal("parsed POST structure result", result, err)
			}
		})
	}
}

func TestProviderRealCredentialObservationArchived874(t *testing.T) {
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
		t.Fatal("frozen raw collection changed")
	}
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
		t.Fatal(err)
	}
	verifiedFields, projections := 0, 0
	for _, input := range restored.Inputs.Request.Inputs {
		if input.HTTP == nil {
			continue
		}
		if input.HTTP.Complete {
			t.Fatal("family completeness upgraded")
		}
		for _, r := range input.HTTP.Records {
			projections++
			if r.RequestVerification != nil && r.RequestVerification.FieldsVerified {
				verifiedFields++
			}
		}
	}
	matched := map[string]bool{}
	for _, n := range public.Evidence.Normalized.Items {
		if (n.RuleID != "F_CRED_POST_STRUCTURE" && n.RuleID != "F_URL_ODD_AUTHORITY") || n.ObservationKind != "complete_http_request" {
			continue
		}
		if n.Status != "not_observed" || n.ExecutionStatus != "executed" || n.Measurements == nil || n.Measurements.SampleCount != 117 || n.Measurements.Values["conflicting_request_groups"] != 51 || len(n.SourceIDs) != 196 {
			t.Fatal("real verified request subset changed", n.RuleID, n.Status, n.ExecutionStatus, n.Measurements, len(n.SourceIDs))
		}
		matched[n.RuleID] = true
		t.Logf("real=true fact=%s execution=%s status=%s request_samples=%d conflicting_groups=51 source_refs=%d family_complete=false public_encode_decode_execute=true semantic_mode=disabled", n.RuleID, n.ExecutionStatus, n.Status, n.Measurements.SampleCount, len(n.SourceIDs))
	}
	if len(matched) != 2 || verifiedFields != 376 || projections != 376 {
		t.Fatal("real field verification count", matched, verifiedFields, projections)
	}
	if dir := os.Getenv("CREDENTIAL_OBSERVATION_ARTIFACT_DIR"); dir != "" {
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
		t.Logf("artifacts=%s parsed_field_verified_projections=%d", dir, verifiedFields)
	}
}
