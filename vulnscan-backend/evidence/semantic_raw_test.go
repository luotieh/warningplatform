package evidence

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestExplicitRawModeRetainsValuesAndNeverPretendsRedacted(t *testing.T) {
	r := semanticFixture(semanticSpecs[0])
	r.InputMode = SemanticRaw
	for n := range r.Subjects[0].Materials {
		r.Subjects[0].Materials[n].Redacted = false
		if r.Subjects[0].Materials[n].Kind == "protocol_request" {
			r.Subjects[0].Materials[n].Text = "POST /command password=LOCAL_SECRET"
		}
	}
	e, _ := NewSemanticEngine(DefaultSemanticConfig())
	result, err := e.Evaluate(context.Background(), r, semanticModelFunc(func(_ context.Context, call SemanticCall) (string, error) {
		if !strings.Contains(call.Prompt, "LOCAL_SECRET") {
			t.Fatal("raw value was silently redacted")
		}
		plan, _ := e.Plan(context.Background(), r)
		task := plan.Tasks[0]
		item := SemanticItem{TaskID: task.ID, Judgement: "support", Strength: "weak", Explanation: "观察到 password=LOCAL_SECRET，不能证明命令执行", MaterialRefs: []string{}, FactRefs: []string{}, AdjudicationRefs: []string{}, Quotes: []SemanticQuote{}}
		for _, m := range task.Materials {
			item.MaterialRefs = append(item.MaterialRefs, m.ID)
			item.Quotes = append(item.Quotes, SemanticQuote{MaterialID: m.ID, Excerpt: m.Text})
			if m.Redacted {
				t.Fatal("raw input falsely marked redacted")
			}
		}
		b, _ := json.Marshal(map[string]any{"items": []SemanticItem{item}})
		return string(b), nil
	}))
	if err != nil || len(result.Findings) != 1 || result.Plan.InputMode != SemanticRaw {
		t.Fatalf("raw contract failed: %v %+v", err, result)
	}
	r.InputMode = ""
	plan, err := e.Plan(context.Background(), r)
	if err != nil || len(plan.Tasks) != 0 {
		t.Fatal("default redacted mode accepted undeclared raw text")
	}
	r.InputMode = "invalid"
	if _, err = e.Plan(context.Background(), r); err == nil {
		t.Fatal("unknown input mode accepted")
	}
}
