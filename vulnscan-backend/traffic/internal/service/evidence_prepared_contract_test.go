package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
)

func preparedContractFixture(t *testing.T) PreparedEvidenceBundle {
	t.Helper()
	raw, err := os.ReadFile("testdata/prepared-controlled-http.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodePreparedEvidence(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPreparedContractRejectsInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*PreparedEvidenceBundle)
	}{
		{"scope", func(b *PreparedEvidenceBundle) { b.Inputs.Request.Inputs[0].Scope.DeviceID = "" }},
		{"ioc_cross_object", func(b *PreparedEvidenceBundle) { b.Inputs.Manifest.PhaseOne.Bindings[0].Scope.AssetID = "unrelated" }},
		{"time_range", func(b *PreparedEvidenceBundle) {
			b.Inputs.Request.Inputs[0].Window.End = b.Inputs.Request.Inputs[0].Window.Start
		}},
		{"duplicate_source", func(b *PreparedEvidenceBundle) {
			b.Inputs.Manifest.PhaseOne.Sources = append(b.Inputs.Manifest.PhaseOne.Sources, b.Inputs.Manifest.PhaseOne.Sources[0])
		}},
		{"forged_source", func(b *PreparedEvidenceBundle) {
			for i := range b.Inputs.SemanticMaterials.Subjects {
				for j := range b.Inputs.SemanticMaterials.Subjects[i].Materials {
					m := &b.Inputs.SemanticMaterials.Subjects[i].Materials[j]
					if m.Kind == "protocol_request" {
						m.Provenance.SourceIDs = []string{"invented-hit"}
						return
					}
				}
			}
		}},
		{"transaction_relation", func(b *PreparedEvidenceBundle) {
			b.Inputs.Request.Inputs[0].HTTP.Records[0].RedirectVerified = true
			b.Inputs.Request.Inputs[0].HTTP.Records[0].RedirectToTransactionID = "missing"
		}},
		{"coverage", func(b *PreparedEvidenceBundle) { b.Coverage[0].Complete = !b.Coverage[0].Complete }},
		{"version", func(b *PreparedEvidenceBundle) { b.SchemaVersion = "unknown" }},
		{"material_window", func(b *PreparedEvidenceBundle) {
			b.Inputs.SemanticMaterials.Subjects[0].Materials[0].Window.End = b.Inputs.SemanticMaterials.Subjects[0].Window.End.Add(time.Hour)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := preparedContractFixture(t)
			tc.mutate(&b)
			b.Seal()
			if err := b.Validate(); err == nil {
				t.Fatal("invalid contract accepted")
			}
		})
	}
	b := preparedContractFixture(t)
	raw, _ := json.Marshal(b)
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	delete(object, "coverage")
	raw, _ = json.Marshal(object)
	if _, err := DecodePreparedEvidence(bytes.NewReader(raw)); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatal("missing required field accepted", err)
	}
	if _, err := DecodePreparedEvidence(strings.NewReader(strings.Repeat(" ", preprocessDecodedBytes+1))); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatal("budget not enforced", err)
	}
}

func TestPreparedEvidenceWithoutStore(t *testing.T)        { TestPreparedEvidenceMockNoStore(t) }
func TestPreparedVsFormalPipelineEquivalence(t *testing.T) { TestPreparedEvidenceFormalParity(t) }

func TestPreparedSemanticExecutionModes(t *testing.T) {
	b := preparedContractFixture(t)
	panicModel := reportSemanticModelFunc(func(context.Context, evidence.SemanticCall) (string, error) {
		t.Error("disabled model invoked")
		return "", nil
	})
	if _, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled, SemanticModel: panicModel}); err != nil {
		t.Fatal(err)
	}
	for _, o := range []PreparedExecutionOptions{{SemanticMode: PreparedSemanticStub}, {SemanticMode: PreparedSemanticLive}, {SemanticMode: "bad"}, {Persist: true}} {
		if _, err := ExecutePreparedEvidence(context.Background(), b, o); err == nil {
			t.Fatal("invalid mode accepted")
		}
	}
}

func TestPreparedContractExport(t *testing.T) {
	paths := PreparedInputFieldMap()
	if len(paths) != 82 {
		t.Fatal("catalog mapping incomplete")
	}
	for _, r := range paths {
		if len(r.JSONPaths) == 0 {
			t.Fatal("unmapped rule", r.ID)
		}
		for _, p := range r.JSONPaths {
			if strings.Contains(p, "node_id") || strings.Contains(p, "NodeID") {
				t.Fatal("stale field path", p)
			}
		}
	}
	dir := os.Getenv("EVIDENCE_V21_OUTPUT")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	b := preparedContractFixture(t)
	out, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"prepared-evidence.schema.json": PreparedEvidenceJSONSchema(), "normalized-evidence.schema.json": NormalizedExecutionJSONSchema(), "input-field-map.json": paths, "prepared-evidence.example.json": b, "mock-execution-result.json": out} {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNormalizedExecutionInvariantsAndProjection(t *testing.T) {
	b := preparedContractFixture(t)
	out, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Contract == nil || out.Contract.InputDigest == "" {
		t.Fatal("missing normalized contract")
	}
	for _, item := range out.Evidence.Normalized.Items {
		key := out.Contract.SourceIndex[item.ID]
		if digest(out.Contract.SourceSets[key]) != digest(item.SourceIDs) {
			t.Fatal("source index mismatch", item.ID)
		}
	}
	if out.Evidence.Essence != nil {
		for _, item := range out.Evidence.Essence.Items {
			found := false
			for _, full := range out.Evidence.Normalized.Items {
				if full.ReportID == item.ID {
					found = true
				}
			}
			if !found {
				t.Fatal("projection is not in full ledger", item.ID)
			}
		}
	}
	for _, mode := range []string{"duplicate", "non_joint_score", "missing_score", "score_total"} {
		t.Run(mode, func(t *testing.T) {
			mutated := out
			mutated.Evidence.Normalized.Items = append([]evidence.UnifiedEvidence(nil), out.Evidence.Normalized.Items...)
			switch mode {
			case "duplicate":
				mutated.Evidence.Normalized.Items = append(mutated.Evidence.Normalized.Items, mutated.Evidence.Normalized.Items[0])
			case "non_joint_score":
				mutated.Evidence.Normalized.Items[0].Kind = "fact"
				mutated.Evidence.Normalized.Items[0].ScoreContribution = 1
			case "missing_score":
				mutated.Evidence.Normalized.Items[0].Kind = "joint"
				mutated.Evidence.Normalized.Items[0].TerminalStatus = "missing"
				mutated.Evidence.Normalized.Items[0].ScoreContribution = 1
			case "score_total":
				for i := range mutated.Evidence.Normalized.Items {
					if mutated.Evidence.Normalized.Items[i].Kind == "joint" {
						mutated.Evidence.Normalized.Items[i].ScoreContribution++
						break
					}
				}
			}
			if ValidatePreparedExecution(b, mutated) == nil {
				t.Fatal("invalid normalized ledger accepted")
			}
		})
	}
}

func TestEvidencePipelineIndexedPageIntegrityAndLegacyRead(t *testing.T) {
	s := phaseOneFixture(t)
	b := preparedContractFixture(t)
	out, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	a := *out.Evidence.Pipeline
	if err = s.persistPipelineJournal(context.Background(), a.Key, b.Event.EventID, pipelineJournal{Audit: a, Evidence: out.Evidence}); err != nil {
		t.Fatal(err)
	}
	doc := ReportDocument{EventID: b.Event.EventID, Evidence: ReportEvidenceBundle{Pipeline: &a}}
	indexed, err := s.ReportEvidenceDetails(context.Background(), doc, 10, 50)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := s.Store.AggregateRecord(context.Background(), "evidence_pipeline", a.Key)
	if err != nil {
		t.Fatal(err)
	}
	var manifest pipelineJournalManifest
	if err = json.Unmarshal(r.Value, &manifest); err != nil {
		t.Fatal(err)
	}
	saved := append([]string(nil), manifest.PageHashes...)
	manifest.PageHashes = nil
	manifest.TotalItems = 0
	r.Value, _ = json.Marshal(manifest)
	if err = s.Store.PutAggregateRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	legacy, err := s.ReportEvidenceDetails(context.Background(), doc, 10, 50)
	if err != nil || digest(indexed.Items) != digest(legacy.Items) {
		t.Fatal("legacy read changed sources or values", err)
	}
	manifest.PageHashes = saved
	manifest.TotalItems = len(out.Evidence.Normalized.Items)
	r.Value, _ = json.Marshal(manifest)
	if err = s.Store.PutAggregateRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	part, _, _ := s.Store.AggregateRecord(context.Background(), "evidence_pipeline_page", a.Key+":0")
	part.Value = []byte(`"corrupted"`)
	if err = s.Store.PutAggregateRecord(context.Background(), part); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReportEvidenceDetails(context.Background(), doc, 0, 50); err == nil {
		t.Fatal("corrupted indexed page accepted")
	}
}

func TestPreparedIndependentContactKindsNeverMix(t *testing.T) {
	b := preparedContractFixture(t)
	m := *b.Inputs.Manifest.PhaseOne
	m.Contacts = nil
	base := b.Inputs.Manifest.PhaseOne.CurrentContacts[0]
	for _, kind := range []string{"tcp_initiation", "complete_http_request"} {
		for i := 0; i < 24; i++ {
			c := base
			c.ID = fmt.Sprintf("%s-%d", kind, i)
			c.HitID = c.ID
			c.Kind = kind
			c.Time = base.Time.Add(time.Duration(i) * time.Minute)
			m.Contacts = append(m.Contacts, c)
		}
	}
	fs, err := pipelineIndependentTemporalFacts(context.Background(), b.Snapshot, m)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.ObservationKind] = true
		if f.Measurements.SampleCount > 24 {
			t.Fatal("different communication populations mixed", f)
		}
	}
	if len(seen) != 2 || len(fs) != 4 {
		t.Fatal("missing independent population", seen, len(fs))
	}
}
