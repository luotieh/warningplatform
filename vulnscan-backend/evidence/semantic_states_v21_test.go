package evidence

import (
	"context"
	"testing"
)

func TestV21SemanticRolesAndNeutralStates(t *testing.T) {
	for _, spec := range semanticSpecs {
		for _, judgement := range []string{"support", "neutral", "contradict"} {
			t.Run(spec.Key.String()+"/"+judgement, func(t *testing.T) {
				out, err := semanticTestEngine(t).Evaluate(context.Background(), semanticFixture(spec), semanticModelFunc(func(_ context.Context, c SemanticCall) (string, error) {
					return semanticResponse(c, func(i *SemanticItem) {
						i.Judgement = judgement
						if judgement == "neutral" {
							i.Strength = "none"
						}
					}), nil
				}))
				if err != nil || len(out.Findings) != 1 {
					t.Fatal(err, out)
				}
				n := Normalize(nil, &out)
				found := false
				for _, u := range n.Items {
					if u.TaskID != out.Findings[0].TaskID {
						continue
					}
					found = true
					if u.ExecutionStatus != "accepted" || u.StructureValidation != "passed" {
						t.Fatal("lost execution", u)
					}
					expected := judgement
					if judgement == "support" {
						expected = "observed"
						if spec.ExplanationOnly {
							expected = "explanation"
						}
					}
					if u.TerminalStatus != expected {
						t.Fatal("wrong terminal", expected, u)
					}
					if u.RiskSupportEligible != (judgement == "support" && !spec.ExplanationOnly && out.Findings[0].DuplicateOf == "") {
						t.Fatal("wrong risk eligibility", u)
					}
					if u.ScoreContribution != 0 || u.ScoreEligible {
						t.Fatal("S bypassed C", u)
					}
				}
				if !found {
					t.Fatal("no normalized task")
				}
			})
		}
	}
}

func TestNormalizedFactIdentityIncludesIOCAndObservationKind(t *testing.T) {
	r, c := fullFixture(BeaconPeriodic)
	f := contractFinding(t, r, c)
	a, b, d := f, f, f
	a.IOCType = "ip"
	a.IOCValue = "192.0.2.1"
	a.ObservationKind = "tcp_initiation"
	b.IOCType = "domain"
	b.IOCValue = "example.test"
	b.ObservationKind = "tcp_initiation"
	d.IOCType = a.IOCType
	d.IOCValue = a.IOCValue
	d.ObservationKind = "complete_http_request"
	n := Normalize([]Finding{a, b, d}, nil)
	seen := map[string]bool{}
	for _, u := range n.Items {
		if seen[u.ID] {
			t.Fatal("different IOC or contact unit collapsed", u)
		}
		seen[u.ID] = true
	}
}
