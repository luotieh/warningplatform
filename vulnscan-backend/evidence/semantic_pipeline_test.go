package evidence

import (
	"context"
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestSemanticPipelineBoundedWorkersAndPanicIsolation(t *testing.T) {
	r := semanticFixture(semanticSpecs[0])
	base := r.Subjects[0]
	for _, id := range []string{"second", "third", "fourth"} {
		s := base
		s.ID = id
		s.PropositionID = id
		r.Subjects = append(r.Subjects, s)
	}
	cfg := DefaultSemanticConfig()
	cfg.ReportHistory = true
	cfg.ReportBatchSize = 1
	cfg.MaxTasks = 8
	cfg.MaxConcurrentBatches = 2
	engine, err := NewSemanticEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var active, peak atomic.Int32
	model := semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		var envelope struct {
			Tasks []SemanticTask `json:"tasks"`
		}
		if json.Unmarshal([]byte(call.Prompt), &envelope) != nil {
			t.Error("bad prompt")
		}
		if envelope.Tasks[0].SubjectID == "second" {
			panic("controlled model failure")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
		return semanticResponse(call, nil), nil
	})
	result, err := engine.Evaluate(context.Background(), r, model)
	if err != nil || result.Calls != 4 || len(result.Findings) != 3 || peak.Load() > 2 || peak.Load() < 2 || len(result.Batches) != 4 {
		t.Fatal("worker bound/isolation", err, result.Calls, len(result.Findings), peak.Load(), len(result.Batches))
	}
	failed := 0
	for _, x := range result.Plan.Executions {
		if x.Reason == "semantic_batch_panic" {
			failed++
		}
	}
	if failed != 1 {
		t.Fatal("panic not localized", result.Plan.Executions)
	}
	for _, batch := range result.Batches {
		if batch.TokenCountKnown || batch.InputBytes <= 0 || len(batch.TaskIDs) != 1 {
			t.Fatal("invented token count/missing batch provenance", batch)
		}
	}
}

func TestSemanticPipelineCancellationAndTokenBudgets(t *testing.T) {
	cfg := DefaultSemanticConfig()
	cfg.MaxInputTokens = 100
	if _, err := NewSemanticEngine(cfg); err == nil {
		t.Fatal("token limit without tokenizer accepted")
	}
	cfg.CountTokens = func(string, string) (int, error) { return 101, nil }
	engine, err := NewSemanticEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Plan(context.Background(), semanticFixture(semanticSpecs[0]))
	if err != nil || len(plan.Tasks) != 0 {
		t.Fatal("token budget exceeded", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = engine.Evaluate(ctx, semanticFixture(semanticSpecs[0]), nil); err != context.Canceled {
		t.Fatal("cancellation lost", err)
	}
}

func TestNormalizedTerminalCatalogHasNoImplicitNegatives(t *testing.T) {
	n := Normalize(nil, nil)
	if len(n.Items) != 82 {
		t.Fatal("catalog omitted", len(n.Items))
	}
	for _, item := range n.Items {
		if item.TerminalStatus != "missing" || item.ScoreEligible || item.ScoreContribution != 0 {
			t.Fatal("empty inputs became evidence", item)
		}
	}
}

func TestPipelineCatalogExport(t *testing.T) {
	if len(Definitions()) != 59 || len(SemanticDefinitions()) != 23 {
		t.Fatal("catalog drift")
	}
	path := os.Getenv("EVIDENCE_PIPELINE_CATALOG_OUTPUT")
	if path == "" {
		return
	}
	facts := []map[string]any{}
	for _, d := range Definitions() {
		facts = append(facts, map[string]any{"definition": d, "input_families": FactInputs(d.ID), "entry": "evidence.Engine.Evaluate/evaluateFactSafely", "field_validation": "existing per-rule gates; raw subject and provenance verified by snapshot adapter"})
	}
	raw, err := json.MarshalIndent(map[string]any{"rule_version": RuleVersion, "semantic_version": SemanticVersion, "normalization_version": NormalizationVersion, "facts": facts, "slots": SemanticDefinitions(), "semantic_input_contracts": SemanticInputContracts()}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
