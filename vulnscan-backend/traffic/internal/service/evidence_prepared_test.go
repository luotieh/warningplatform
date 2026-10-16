package service

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
)

func TestPreparedEvidenceFormalParity(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	rows := []map[string]any{}
	for i := 0; i < 6; i++ {
		rows = append(rows, phaseOneWire(t, at.Add(time.Duration(i)*time.Minute), uint32(100+i*500), phaseOneHTTP("cmd=636174202f6574632f706173737764"), false, false))
	}
	snap := phaseOneInstallSnapshot(t, s, "prepared-controlled-http", 1, rows)
	opts := DefaultReportSemanticOptions()
	opts.ModelVersion = "controlled-stub-not-real-model"
	s.ReportSemantics = &opts
	model := reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		return acceptedSemanticResponse(t, call), nil
	})
	s.SemanticModel = model
	p := EvidencePipeline{Services: s}
	b, err := p.PrepareEvidenceBundle(context.Background(), snap.EventID)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err = EncodePreparedEvidence(&encoded, b); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePreparedEvidence(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Inputs.SemanticMaterials == nil || len(decoded.Inputs.SemanticMaterials.Subjects) == 0 {
		t.Fatal("L2 lacks semantic materials")
	}
	var raw, body bool
	for _, h := range decoded.Inputs.HTTP {
		raw = raw || h.Raw != ""
		body = body || h.Body != ""
	}
	if !raw || !body {
		t.Fatal("HTTP hidden JSON fields lost")
	}
	formal, err := p.Execute(context.Background(), snap.EventID, EvidencePipelineOptions{Persist: true})
	if err != nil {
		t.Fatal(err)
	}
	offline, err := ExecutePreparedEvidence(context.Background(), decoded, PreparedExecutionOptions{SemanticModel: model})
	if err != nil {
		t.Fatal(err)
	}
	if digest(formal.Evaluation.Result) != digest(offline.Evaluation.Result) {
		t.Fatal("formal/offline F results differ")
	}
	if digest(formal.Semantics.Result.Findings) != digest(offline.Semantics.Result.Findings) {
		t.Fatal("formal/offline accepted S differ")
	}
	if digest(formal.Evidence.PhaseOne.Result.Units) != digest(offline.Evidence.PhaseOne.Result.Units) || formal.Evidence.PhaseOne.Result.Score != offline.Evidence.PhaseOne.Result.Score {
		t.Fatal("formal/offline C differs")
	}
	if digest(formal.Evidence.Pipeline.Checks) != digest(offline.Evidence.Pipeline.Checks) {
		t.Fatal("catalog terminal states differ")
	}
	if digest(formal.Semantics.Result.Plan) != digest(offline.Semantics.Result.Plan) {
		t.Fatal("formal/offline semantic plans differ")
	}
	if digest(formal.Evidence.Normalized) != digest(offline.Evidence.Normalized) {
		for i, f := range formal.Evidence.Normalized.Items {
			if digest(f) != digest(offline.Evidence.Normalized.Items[i]) {
				t.Fatalf("normalized instance differs: formal=%+v offline=%+v", f, offline.Evidence.Normalized.Items[i])
			}
		}
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal("execution mutated caller bundle", err)
	}
	if path := os.Getenv("EVIDENCE_PREPARED_FIXTURE_OUTPUT"); path != "" {
		var buf bytes.Buffer
		if err := EncodePreparedEvidence(&buf, decoded); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// This test reads only a checked-in prepared JSON. It constructs no Services,
// Store, database, event installer, snapshot reader or report service.
func TestPreparedEvidenceMockNoStore(t *testing.T) {
	raw, err := os.ReadFile("testdata/prepared-controlled-http.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodePreparedEvidence(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	model := reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		calls++
		return acceptedSemanticResponse(t, call), nil
	})
	out, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticStub, SemanticModel: model})
	if err != nil {
		t.Fatal(err)
	}
	a := out.Evidence.Pipeline
	if calls == 0 || a.Completed != 82 || a.ExpectedFacts != 59 || a.ExpectedSemantics != 23 || a.Persisted {
		t.Fatal("storage-free execution incomplete", calls, a)
	}
	if out.Semantics.Status == "planned" || len(out.Semantics.Result.Findings) == 0 {
		t.Fatal("mock semantics not validated")
	}
	if a.Metrics.SnapshotReadPages != 0 || a.Metrics.HistoryMetadataPages != 0 || a.Metrics.JSONDecodes != 0 || a.Metrics.WireFrameDecodes != 0 || a.Metrics.HTTPRequestParses != 0 || a.Metrics.DNSMessageParses != 0 {
		t.Fatal("L3 performed retrieval/parsing", a.Metrics)
	}
	if out.Evidence.PhaseOne == nil || len(out.Evidence.Normalized.Items) < 82 {
		t.Fatal("normalization/C missing")
	}
	points := 0
	for _, item := range out.Evidence.Normalized.Items {
		points += item.ScoreContribution
	}
	if points != out.Evidence.PhaseOne.Result.Score {
		t.Fatal("joint score mismatch")
	}
	second, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticMode: PreparedSemanticStub, SemanticModel: model})
	if err != nil || digest(out.Evidence.Normalized) != digest(second.Evidence.Normalized) {
		t.Fatal("replay not deterministic", err)
	}
	planned, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{})
	if err != nil || planned.Semantics.Status != "planned" || planned.Semantics.Result == nil || planned.Semantics.Result.Calls != 0 || len(planned.Semantics.Result.Plan.Tasks) == 0 {
		t.Fatal("no-model incorrectly treated as completed semantics", err)
	}
	if path := os.Getenv("EVIDENCE_PREPARED_RESULT_OUTPUT"); path != "" {
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPreparedEvidenceImportRejectsInvalidBindings(t *testing.T) {
	raw, err := os.ReadFile("testdata/prepared-controlled-http.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*PreparedEvidenceBundle)
	}{
		{"snapshot", func(b *PreparedEvidenceBundle) { b.Inputs.Request.SnapshotVersion++ }},
		{"watermark", func(b *PreparedEvidenceBundle) { b.Inputs.Manifest.Watermark++ }},
		{"catalog", func(b *PreparedEvidenceBundle) { b.Inputs.Request.Facts[0] = b.Inputs.Request.Facts[1] }},
		{"unexpanded", func(b *PreparedEvidenceBundle) { b.Inputs.Manifest.PhaseOne.Expanded = false }},
		{"contact_source", func(b *PreparedEvidenceBundle) { b.Inputs.Manifest.PhaseOne.Contacts[0].Snapshot.Watermark++ }},
		{"semantic_event", func(b *PreparedEvidenceBundle) { b.Inputs.SemanticMaterials.EventID = "other" }},
		{"precomputed_verdict", func(b *PreparedEvidenceBundle) {
			b.Inputs.SemanticMaterials.Subjects[0].Facts = []evidence.Finding{{Status: evidence.Observed}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := DecodePreparedEvidence(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&b)
			b.Seal()
			if _, err = ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{}); err == nil {
				t.Fatal("accepted invalid prepared identity")
			}
		})
	}
	if _, err := DecodePreparedEvidence(strings.NewReader(strings.Replace(string(raw), "prepared-controlled-http", "tampered", 1))); err == nil {
		t.Fatal("digest tampering accepted")
	}
}

func TestPreparedEvidenceModelFailureIsolated(t *testing.T) {
	raw, err := os.ReadFile("testdata/prepared-controlled-http.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodePreparedEvidence(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := ExecutePreparedEvidence(context.Background(), b, PreparedExecutionOptions{SemanticModel: reportSemanticModelFunc(func(context.Context, evidence.SemanticCall) (string, error) { return "invalid JSON", nil })})
	if err != nil {
		t.Fatal(err)
	}
	if out.Evidence.Pipeline.Completed != 82 || out.Evidence.Pipeline.Counts["execution_error"] == 0 || out.Evaluation.Status != "evaluated" {
		t.Fatal("model error hid F or became negative")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExecutePreparedEvidence(ctx, b, PreparedExecutionOptions{}); err == nil {
		t.Fatal("cancellation swallowed")
	}
}
