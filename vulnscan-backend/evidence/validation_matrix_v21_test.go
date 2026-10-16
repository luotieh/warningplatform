package evidence

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Reuse the actual positive/negative fixtures and engines. Each exported row
// corresponds to assertions that ran, never to a manufactured finding.
func TestV21FactValidationMatrix(t *testing.T) {
	rows := [][]string{{"rule_id", "rule_kind", "scenario", "fixture", "expected_status", "actual_status", "test_result", "real_material_available", "real_execution_verified", "real_model_verified", "remaining_blocker"}}
	for _, id := range SupportedFacts() {
		for _, scenario := range []string{"positive", "negative", "missing", "binding", "boundary"} {
			t.Run(string(id)+"/"+scenario, func(t *testing.T) {
				r, c := fullFixture(id)
				expected := Observed
				switch scenario {
				case "negative":
					r, c = negativeFixture(id)
					expected = NotObserved
				case "missing":
					r = testRequest()
					r.Facts = []FactID{id}
					r.Quality = Quality{}
					expected = Missing
				case "binding":
					expected = Missing
					if groupRule(id) {
						r.Groups[0].Verified = false
					} else {
						expected = Status("error")
						for i := range r.Inputs {
							r.Inputs[i].Scope.AssetID = "different-asset"
						}
						if id == MultiDayPersist || id == BeaconPeriodic {
							for i := range r.Hits {
								r.Hits[i].OccurredAt = time.Time{}
							}
						}
					}
				case "boundary":
					r.SnapshotVersion = 0
				}
				engine, err := NewEngine(c)
				if err != nil {
					t.Fatal(err)
				}
				out, err := engine.Evaluate(context.Background(), r)
				actual := "error"
				if err == nil && len(out.Findings) == 1 {
					actual = string(out.Findings[0].Status)
				}
				pass := false
				if expected == Status("error") || scenario == "boundary" {
					pass = err != nil
					expected = Status("error")
				} else {
					pass = err == nil && actual == string(expected)
				}
				if !pass {
					t.Fatalf("expected %s got %s err=%v result=%+v", expected, actual, err, out)
				}
				rows = append(rows, []string{string(id), "F", scenario, "fullFixture/negativeFixture/typed mutation", string(expected), actual, "passed", "not_claimed", "not_claimed", "not_applicable", "production material acceptance separate; boundary here is invalid snapshot version"})
				if scenario == "positive" || scenario == "negative" {
					exportFixture(t, string(id)+"-"+scenario, map[string]any{"request": r, "config": c, "expected_status": expected, "controlled": true})
				}
			})
		}
	}
	exportMatrix(t, "f-validation-cases.csv", rows)
}

func TestV21SemanticValidationMatrix(t *testing.T) {
	rows := [][]string{{"rule_id", "rule_kind", "scenario", "fixture", "expected_status", "actual_status", "test_result", "real_material_available", "real_execution_verified", "real_model_verified", "remaining_blocker"}}
	for _, spec := range semanticSpecs {
		for _, scenario := range []string{"support", "contradict", "neutral", "missing", "invented_reference", "cross_transaction", "invalid_strength", "model_failure"} {
			t.Run(spec.Key.String()+"/"+scenario, func(t *testing.T) {
				r := semanticFixture(spec)
				if scenario == "support" {
					exportFixture(t, spec.Key.ID+"-"+spec.Key.Target+"-"+spec.Key.Subtype, map[string]any{"request": r, "controlled_prerequisite_facts": true, "real_model": false})
				}
				if scenario == "missing" {
					r.Subjects[0].Materials = nil
				}
				if scenario == "cross_transaction" {
					raw, _ := json.Marshal(r.Subjects[0])
					var second SemanticSubject
					_ = json.Unmarshal(raw, &second)
					second.ID += "-other"
					second.PropositionID += "-other"
					for i := range second.Materials {
						m := &second.Materials[i]
						m.ID += "-other"
						for j := range m.RelatedIDs {
							m.RelatedIDs[j] += "-other"
						}
						for j := range m.DecodeSteps {
							m.DecodeSteps[j].InputID += "-other"
							m.DecodeSteps[j].OutputID += "-other"
						}
						if m.TransactionID != "" {
							m.TransactionID += "-other"
						}
					}
					r.Subjects = append(r.Subjects, second)
				}
				out, err := semanticTestEngine(t).Evaluate(context.Background(), r, semanticModelFunc(func(_ context.Context, call SemanticCall) (string, error) {
					if scenario == "model_failure" {
						return "", fmt.Errorf("controlled failure")
					}
					var delivered struct {
						Tasks []SemanticTask `json:"tasks"`
					}
					_ = json.Unmarshal([]byte(call.Prompt), &delivered)
					if scenario == "cross_transaction" && len(delivered.Tasks) != 2 {
						t.Fatalf("cross-transaction fixture did not plan two tasks: %d", len(delivered.Tasks))
					}
					return semanticResponse(call, func(i *SemanticItem) {
						switch scenario {
						case "neutral":
							i.Judgement = "neutral"
							i.Strength = "none"
						case "contradict":
							i.Judgement = "contradict"
						case "invented_reference":
							i.MaterialRefs = []string{"invented-material"}
						case "cross_transaction":
							i.MaterialRefs = []string{"other-transaction-material"}
							if len(delivered.Tasks) > 1 {
								for _, other := range delivered.Tasks {
									if other.ID != i.TaskID {
										i.MaterialRefs = []string{other.Materials[0].ID}
										break
									}
								}
							}
						case "invalid_strength":
							i.Strength = "certain_success"
						}
					}), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				actual := "rejected"
				expected := "rejected"
				if len(out.Findings) > 0 {
					actual = "accepted"
				}
				switch scenario {
				case "support", "contradict", "neutral":
					expected = "accepted"
					if len(out.Findings) != 1 || out.Findings[0].StructureValidation != "passed" {
						t.Fatal("valid semantic result not accepted", out)
					}
					if err := ValidateSemanticResult(out.Plan, out); err != nil {
						t.Fatal(err)
					}
				case "missing":
					expected = "not_planned"
					actual = "not_planned"
					if len(out.Plan.Tasks) != 0 || out.Calls != 0 {
						t.Fatal("missing material called model")
					}
				default:
					if len(out.Findings) != 0 {
						t.Fatal("invalid response accepted", out)
					}
				}
				if actual != expected {
					t.Fatal(actual, expected)
				}
				rows = append(rows, []string{spec.Key.String(), "S", scenario, "semanticFixture + controlled model response", expected, actual, "passed", "not_claimed", "not_claimed", "false", "requires live model and human-labelled accuracy benchmark"})
			})
		}
	}
	exportMatrix(t, "s-validation-cases.csv", rows)
}

func exportFixture(t *testing.T, name string, value any) {
	t.Helper()
	if dir := os.Getenv("EVIDENCE_V21_OUTPUT"); dir != "" {
		dir = filepath.Join(dir, "mock-fixtures")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func exportMatrix(t *testing.T, name string, rows [][]string) {
	t.Helper()
	if dir := os.Getenv("EVIDENCE_V21_OUTPUT"); dir != "" {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		w := csv.NewWriter(f)
		w.WriteAll(rows)
		if err = w.Error(); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
