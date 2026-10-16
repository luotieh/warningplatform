package service

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
)

func TestEvidencePipelineAll82AndModelCacheIsolation(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	rows := []map[string]any{}
	for i := 0; i < 6; i++ {
		rows = append(rows, phaseOneWire(t, at.Add(time.Duration(i)*time.Minute), uint32(100+i*500), phaseOneHTTP("cmd=636174202f6574632f706173737764"), false, false))
	}
	snap := phaseOneInstallSnapshot(t, s, "pipeline-all82", 1, rows)
	reads := &evidenceReadCounter{Store: s.Store}
	s.Store = reads
	calls := 0
	s.SemanticModel = reportSemanticModelFunc(func(_ context.Context, c evidence.SemanticCall) (string, error) {
		calls++
		return acceptedSemanticResponse(t, c), nil
	})
	opts := DefaultReportSemanticOptions()
	opts.ModelVersion = "controlled-v1"
	s.ReportSemantics = &opts
	p, err := (EvidencePipeline{Services: s}).Execute(context.Background(), snap.EventID, EvidencePipelineOptions{Persist: true})
	if err != nil {
		t.Fatal(err)
	}
	a := p.Evidence.Pipeline
	if a == nil || len(a.Checks) != 82 || !a.Persisted {
		t.Fatal("audit catalog/persistence", a)
	}
	seen := map[string]bool{}
	for _, check := range a.Checks {
		if seen[check.ID] || check.Status == "" {
			t.Fatal("duplicate/unfinalized catalog entry", check)
		}
		seen[check.ID] = true
	}
	if len(p.Evaluation.Manifest.FactCoverage) != 59 {
		t.Fatal("59 F not requested", len(p.Evaluation.Manifest.FactCoverage))
	}
	if p.Evaluation.Manifest.JSONDecodeCount != 6 || p.Evaluation.Manifest.WireFrameDecodeCount != 6 || p.Evaluation.Manifest.HTTPRequestParseCount != 6 {
		t.Fatal("raw parsed repeatedly", p.Evaluation.Manifest.JSONDecodeCount, p.Evaluation.Manifest.WireFrameDecodeCount, p.Evaluation.Manifest.HTTPRequestParseCount)
	}
	for _, u := range p.Evidence.Normalized.Items {
		if u.Kind == "fact" || u.Kind == "semantic" {
			if u.TerminalStatus == "" {
				t.Fatal("missing terminal state", u.RuleID)
			}
			if u.ScoreContribution != 0 || u.ScoreEligible {
				t.Fatal("F/S bypassed C score gate")
			}
		}
	}
	if path := os.Getenv("EVIDENCE_PIPELINE_CONTROLLED_OUTPUT"); path != "" {
		raw, err := json.MarshalIndent(map[string]any{"fixture": "controlled HTTP; deterministic semantic stub; not a real positive", "audit": p.Evidence.Pipeline, "manifest": p.Evaluation.Manifest, "normalized": p.Evidence.Normalized, "joint": p.Evidence.PhaseOne.Result}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	jointPoints := 0
	for _, u := range p.Evidence.Normalized.Items {
		if u.Kind == "joint" {
			jointPoints += u.ScoreContribution
		}
	}
	if jointPoints != p.Evidence.PhaseOne.Result.Score {
		t.Fatal("normalized contribution differs from policy", jointPoints, p.Evidence.PhaseOne.Result.Score)
	}
	pages, before := reads.hitPages, calls
	opts.ModelVersion = "controlled-v2"
	p2, err := (EvidencePipeline{Services: s}).Execute(context.Background(), snap.EventID, EvidencePipelineOptions{Persist: true})
	if err != nil || reads.hitPages != pages || calls <= before || p2.Semantics.ResultKey == p.Semantics.ResultKey {
		t.Fatal("model change reread raw or reused old model result", err, reads.hitPages, pages, calls, before)
	}
	if p2.Evidence.PhaseOne.Result.Score != p.Evidence.PhaseOne.Result.Score {
		t.Fatal("model version changed deterministic policy")
	}
	warm, err := (EvidencePipeline{Services: s}).Execute(context.Background(), snap.EventID, EvidencePipelineOptions{Persist: true})
	if err != nil || warm.Evidence.Pipeline.Key != p2.Evidence.Pipeline.Key {
		t.Fatal("volatile cache flags changed audit identity", err)
	}
}

func TestEvidencePreprocessRoundTripAndWatermarkInvalidation(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	snap := phaseOneInstallSnapshot(t, s, "preprocess-roundtrip", 1, []map[string]any{phaseOneWire(t, at, 100, phaseOneHTTP("cmd=cat"), false, false)})
	assets, err := s.Store.ListAssetsContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultSnapshotEvidenceOptions()
	opts.ReportMaterialMode = true
	opts.CaptureSemantic = true
	opts.Facts = evidence.SupportedFacts()
	in, err := s.SnapshotEvidenceInput(context.Background(), snap, assets, opts)
	if err != nil || in.Reason != "" {
		t.Fatal(err, in.Reason)
	}
	envelope, err := encodePreprocessed(in, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	out, ok := decodePreprocessed(envelope, "test-key", snap)
	if !ok {
		t.Fatal("valid cache rejected")
	}
	if digest(in.Request) != digest(out.Request) || len(out.SemanticObservations) != 1 || out.Request.Inputs[0].HTTP.Records[0].RawRequest == "" || out.SemanticObservations[0].HTTP.RawRequest == "" {
		t.Fatal("transient protocol fields lost")
	}
	if out.Request.Inputs[0].HTTP.Records[0].ParsedBody != "cmd=cat" {
		t.Fatal("parsed body lost")
	}
	snap.RevisionWatermark++
	if _, ok = decodePreprocessed(envelope, "test-key", snap); ok {
		t.Fatal("new raw revision blessed old preprocessing")
	}
	snap.RevisionWatermark--
	envelope.SHA256 = "corrupt"
	if _, ok = decodePreprocessed(envelope, "test-key", snap); ok {
		t.Fatal("corrupt prepared input accepted")
	}
}

func TestPipelineMissingNeutralDisabledAndRejectedStates(t *testing.T) {
	a := pipelineAudit("missing", SnapshotFactEvaluation{}, ReportSemanticEvaluation{Status: "disabled", Reason: "semantic_execution_disabled"})
	if len(a.Checks) != 82 || a.Counts["missing"] != 59 || a.Counts["skipped"] != 23 {
		t.Fatal(a.Counts)
	}
	slot := evidence.SemanticDefinitions()[0].Key
	sem := ReportSemanticEvaluation{Result: &evidence.SemanticResult{Plan: evidence.SemanticPlan{Executions: []evidence.SemanticExecution{{Slot: slot, TaskID: "T1", Status: "accepted"}}}, Findings: []evidence.SemanticFinding{{SemanticItem: evidence.SemanticItem{TaskID: "T1", Judgement: "neutral"}, StructureValidation: "passed"}}}}
	a = pipelineAudit("neutral", SnapshotFactEvaluation{}, sem)
	for _, check := range a.Checks {
		if check.ID == slot.String() && check.Status != "neutral" {
			t.Fatal("neutral became negative", check)
		}
	}
	sem.Result.Plan.Executions[0].Status = "rejected"
	a = pipelineAudit("invalid", SnapshotFactEvaluation{}, sem)
	if a.Counts["execution_error"] != 1 {
		t.Fatal("rejection became negative", a.Counts)
	}
}

func TestPipelineReportRejectsInventedReferenceAndSuccess(t *testing.T) {
	_, event, b := reportTestBundle(t)
	good := validPipelineAssessment(b)
	for _, tc := range []struct {
		name   string
		mutate func(*ReportAssessment)
	}{
		{"unknown-reference", func(a *ReportAssessment) { a.Supporting[0].EvidenceIDs = []string{"F999"} }},
		{"invented-number", func(a *ReportAssessment) { a.Supporting[0].Explanation = "发生999999次连接" }},
		{"success", func(a *ReportAssessment) { a.ProbabilityReason = "确认攻击成功" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := good
			a.Supporting = append([]ReportReason(nil), good.Supporting...)
			tc.mutate(&a)
			raw, _ := json.Marshal(a)
			if _, err := decodeReportAssessment(string(raw), b); err == nil {
				t.Fatal("invalid final assessment published")
			}
		})
	}
	good.Gaps = []string{"未证明攻击成功"}
	raw, _ := json.Marshal(good)
	if _, err := decodeReportAssessment(string(raw), b); err != nil {
		t.Fatal("qualified gap rejected", err)
	}
	prompt, err := evidenceReportPrompt(event, preparedReportInput{}, b, "")
	if err != nil || !strings.Contains(prompt, "pipeline_audit") || strings.Contains(prompt, "instance_states") {
		t.Fatal("unbounded/uncorrelated report projection", err)
	}
}

func TestEvidencePipelineJournalAndReportProjection(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	snap := phaseOneInstallSnapshot(t, s, "journal-bound", 1, []map[string]any{phaseOneWire(t, at, 100, phaseOneHTTP("cmd=id"), false, false)})
	s.SemanticModel = reportSemanticModelFunc(func(_ context.Context, c evidence.SemanticCall) (string, error) {
		return acceptedSemanticResponse(t, c), nil
	})
	p := phaseOneRun(t, s, snap, true)
	doc := ReportDocument{EventID: snap.EventID, SchemaVersion: reportEvidenceVersion, LayoutVersion: reportFivePartLayout, Evidence: p.Evidence, Assessment: validPipelineAssessment(p.Evidence)}
	before := renderReportMarkdown(doc)
	compact := compactPipelineReport(doc)
	if before != renderReportMarkdown(compact) || len(compact.Evidence.Normalized.Items) != 0 || len(p.Evidence.Normalized.Items) == 0 {
		t.Fatal("projection changed report or mutated audit")
	}
	loaded, loadErr := s.loadPipelineJournal(context.Background(), snap.EventID, p.Evidence.Pipeline.Key)
	if loadErr != nil || digest(loaded.Evidence.Normalized) != digest(p.Evidence.Normalized) {
		t.Fatal("source interning changed normalized evidence", loadErr)
	}
	page, err := s.ReportEvidenceDetails(context.Background(), compact, 0, 10)
	if err != nil || len(page.Items) != 10 || page.Total != len(p.Evidence.Normalized.Items) || len(page.Audit.Checks) != 82 {
		t.Fatal("full audit unavailable", err, page.Total)
	}
	compact.EventID = "another-event"
	if _, err = s.ReportEvidenceDetails(context.Background(), compact, 0, 10); err == nil {
		t.Fatal("cross-event audit accepted")
	}
	compact.EventID = snap.EventID
	record, _, _ := s.Store.AggregateRecord(context.Background(), "evidence_pipeline_chunk", p.Evidence.Pipeline.Key+":0")
	record.Value = []byte(`"corrupt"`)
	if err = s.Store.PutAggregateRecord(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReportEvidenceDetails(context.Background(), compact, 0, 10); err == nil {
		t.Fatal("corrupt audit accepted")
	}
}
func TestEvidencePipelineConfiguredLimits(t *testing.T) {
	s := phaseOneFixture(t)
	s.EvidenceLimits = &EvidencePipelineLimits{PageRows: 3, PageBytes: 1024, RowBytes: 2048, HistorySnapshots: 2}
	v := s.pipelineLimits()
	if v.PageRows != 3 || v.RowBytes != 1024 || v.HistorySnapshots != 2 || v.TotalTimeout <= 0 {
		t.Fatal(v)
	}
	w := &pipelineBoundedWriter{limit: 2, w: &strings.Builder{}}
	if _, err := w.Write([]byte("123")); err == nil {
		t.Fatal("writer exceeded bound")
	}
}

func TestPipelineProjectionOmitsWholeInstancesAndKeepsAudit(t *testing.T) {
	b := ReportEvidenceBundle{Essence: &ReportEssenceBundle{Items: []ReportEssence{{ID: "F001", Name: "large", Summary: strings.Repeat("x", 15000), Details: []string{"D1"}}, {ID: "F002", Name: "small", Summary: "verified fact", Details: []string{"D2"}}}, Details: []ReportEssenceDetail{{ID: "D1"}, {ID: "D2"}}, Trace: []ReportEssenceTrace{{EntryID: "F001", EvidenceID: "F001"}, {EntryID: "F002", EvidenceID: "F002"}}}}
	out := boundedPipelineEssence(b)
	if len(out.Items) != 1 || out.Items[0].ID != "F002" || out.ProjectionOmitted != 1 || len(b.Essence.Items) != 2 || out.Trace[0].EvidenceID != "" {
		t.Fatal("projection sliced a statistic or lost omission", out)
	}
}
