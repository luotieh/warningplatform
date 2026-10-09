package evidence

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestSemanticConfigAndTokenizerErrors(t *testing.T) {
	for _, mode := range []string{"tasks", "input", "output", "material", "tokens", "timeout", "missing_tokenizer"} {
		t.Run(mode, func(t *testing.T) {
			c := DefaultSemanticConfig()
			switch mode {
			case "tasks":
				c.MaxTasks = 24
			case "input":
				c.MaxInputBytes = 1
			case "output":
				c.MaxOutputBytes = 1
			case "material":
				c.MaxMaterialBytes = 1
			case "tokens":
				c.MaxOutputTokens = 0
			case "timeout":
				c.Timeout = 0
			case "missing_tokenizer":
				c.MaxInputTokens = 100
			}
			if _, err := NewSemanticEngine(c); err == nil {
				t.Fatal("invalid budget accepted")
			}
		})
	}
	for _, mode := range []string{"error", "negative"} {
		t.Run(mode, func(t *testing.T) {
			c := DefaultSemanticConfig()
			c.CountTokens = func(string, string) (int, error) {
				if mode == "negative" {
					return -1, nil
				}
				return 0, errors.New("tokenizer unavailable")
			}
			e, _ := NewSemanticEngine(c)
			if _, err := e.Plan(context.Background(), semanticFixture(semanticSpecs[0])); err == nil {
				t.Fatal("tokenizer failure accepted")
			}
		})
	}
}

func TestSemanticDecodeVariantsAndBinding(t *testing.T) {
	for _, mode := range []string{"hex", "base64url", "two_steps", "unknown_encoding", "unrelated_domain", "unrelated_operation", "truncated_decode"} {
		t.Run(mode, func(t *testing.T) {
			slot := 3
			if mode == "unrelated_operation" {
				slot = 14
			}
			r := semanticFixture(semanticSpecs[slot])
			s := &r.Subjects[0]
			byID := map[string]*SemanticMaterial{}
			for i := range s.Materials {
				byID[s.Materials[i].ID] = &s.Materials[i]
			}
			switch mode {
			case "hex":
				byID["encoded_payload"].Text = hex.EncodeToString([]byte("run_status"))
				byID["decode"].DecodeSteps[0].Encoding = "hex"
			case "base64url":
				byID["encoded_payload"].Text = base64.RawURLEncoding.EncodeToString([]byte("run_status"))
				byID["decode"].DecodeSteps[0].Encoding = "base64url"
			case "two_steps":
				middle := *byID["encoded_payload"]
				middle.ID = "middle"
				middle.Text = hex.EncodeToString([]byte("run_status"))
				s.Materials = append(s.Materials, middle)
				for i := range s.Materials {
					if s.Materials[i].ID == "encoded_payload" {
						s.Materials[i].Text = base64.StdEncoding.EncodeToString([]byte(middle.Text))
					}
					if s.Materials[i].ID == "decode" {
						s.Materials[i].DecodeSteps = []SemanticDecodeStep{{"base64", "encoded_payload", "middle"}, {"hex", "middle", "decoded_payload"}}
					}
				}
			case "unknown_encoding":
				byID["decode"].DecodeSteps[0].Encoding = "gzip"
			case "unrelated_domain":
				byID["domain"].RelatedIDs = nil
			case "unrelated_operation":
				byID["operation_context"].RelatedIDs = nil
			case "truncated_decode":
				byID["encoded_payload"].Truncated = true
			}
			p, err := semanticTestEngine(t).Plan(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			valid := mode == "hex" || mode == "base64url" || mode == "two_steps"
			if (len(p.Tasks) == 1) != valid {
				t.Fatalf("unexpected decode eligibility: %+v", p)
			}
		})
	}
}

func TestSemanticStratumActualMessages(t *testing.T) {
	for _, mode := range []string{"bad_json", "other_method", "no_params", "other_id", "wrong_id_type", "no_result"} {
		t.Run(mode, func(t *testing.T) {
			r := semanticFixture(semanticSpecs[10])
			for i := range r.Subjects[0].Materials {
				m := &r.Subjects[0].Materials[i]
				if m.Kind == "stratum_request" {
					switch mode {
					case "bad_json":
						m.Text = "not a protocol message"
					case "other_method":
						m.Text = `{"id":1,"method":"other","params":[]}`
					case "no_params":
						m.Text = `{"id":1,"method":"mining.subscribe"}`
					}
				}
				if m.Kind == "stratum_response" {
					switch mode {
					case "other_id":
						m.Text = `{"id":2,"result":[]}`
					case "wrong_id_type":
						m.Text = `{"id":"1","result":[]}`
					case "no_result":
						m.Text = `{"id":1}`
					}
				}
			}
			p, err := semanticTestEngine(t).Plan(context.Background(), r)
			if err != nil || len(p.Tasks) != 0 || p.Executions[0].Reason != "invalid_stratum_messages" {
				t.Fatalf("%v %+v", err, p)
			}
		})
	}
}

func TestSemanticGroupAndHistoryLimits(t *testing.T) {
	for _, slot := range []int{17, 19, 21, 22} {
		t.Run(semanticSpecs[slot].Key.String(), func(t *testing.T) {
			r := semanticFixture(semanticSpecs[slot])
			s := &r.Subjects[0]
			for n := 0; n < 6; n++ {
				m := s.Materials[0]
				m.ID = string(rune('a' + n))
				m.AssetID = m.ID
				m.EventID = "event-" + m.ID
				m.AdjudicationID = "review-" + m.ID
				s.Materials = append(s.Materials, m)
			}
			p, err := semanticTestEngine(t).Plan(context.Background(), r)
			if err != nil || len(p.Tasks) != 0 {
				t.Fatalf("limit bypass: %v %+v", err, p)
			}
		})
	}
}

func TestSemanticPrimaryQuoteCannotBeReplacedByContext(t *testing.T) {
	r := semanticFixture(semanticSpecs[0])
	for i := range r.Subjects[0].Materials {
		if r.Subjects[0].Materials[i].Kind == "pair" {
			r.Subjects[0].Materials[i].Provenance.Verified = false
		}
	}
	got, err := semanticTestEngine(t).Evaluate(context.Background(), r, semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) {
		return semanticResponse(call, func(i *SemanticItem) { i.Quotes = i.Quotes[1:] }), nil
	}))
	if err != nil || len(got.Findings) != 0 || got.Plan.Executions[0].Reason != "missing_primary_material_quote" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestSemanticWorkhoursAlternativeAndSourceValidity(t *testing.T) {
	r := semanticFixture(semanticSpecs[18])
	for i := range r.Subjects[0].Materials {
		if r.Subjects[0].Materials[i].Kind == "time_distribution" {
			r.Subjects[0].Materials[i].Kind = "workhours_active"
		}
	}
	p, err := semanticTestEngine(t).Plan(context.Background(), r)
	if err != nil || len(p.Tasks) != 1 {
		t.Fatalf("workhours alternative: %v %+v", err, p)
	}
	for _, mode := range []string{"not_redacted", "empty_source", "empty_version", "missing_role"} {
		t.Run(mode, func(t *testing.T) {
			r := semanticFixture(semanticSpecs[18])
			m := &r.Subjects[0].Materials[0]
			switch mode {
			case "not_redacted":
				m.Redacted = false
			case "empty_source":
				m.Provenance.SourceIDs = []string{""}
			case "empty_version":
				m.Provenance.Version = ""
			case "missing_role":
				m.Role = ""
			}
			p, err := semanticTestEngine(t).Plan(context.Background(), r)
			if err != nil || len(p.Tasks) != 0 {
				t.Fatalf("invalid source eligible: %v %+v", err, p)
			}
		})
	}
}

func TestSemanticDedupeRetainsDissentAndSelectsStrongest(t *testing.T) {
	r := semanticFixture(semanticSpecs[0])
	r.Slots = append(r.Slots, semanticSpecs[1].Key)
	for _, mode := range []string{"strongest", "dissent"} {
		t.Run(mode, func(t *testing.T) {
			got, err := semanticTestEngine(t).Evaluate(context.Background(), r, semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) {
				return semanticResponse(call, func(i *SemanticItem) {
					if i.TaskID == "T001" {
						i.Strength = "weak"
					}
					if mode == "dissent" && i.TaskID == "T002" {
						i.Judgement = "contradict"
					}
				}), nil
			}))
			if err != nil || len(got.Findings) != 2 {
				t.Fatalf("%v %+v", err, got)
			}
			if mode == "strongest" && (got.Findings[0].DuplicateOf != "T002" || got.Findings[1].DuplicateOf != "") {
				t.Fatal("strongest dedupe lost")
			}
			if mode == "dissent" && (got.Findings[0].DuplicateOf != "" || got.Findings[1].DuplicateOf != "") {
				t.Fatal("dissent hidden")
			}
		})
	}
}

func TestSemanticEngineConcurrentAndNoInputMutation(t *testing.T) {
	e := semanticTestEngine(t)
	r := semanticFixture(semanticSpecs[6])
	before := *r.Subjects[0].Materials[2].Bytes
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := e.Plan(context.Background(), r)
			if err != nil || len(p.Tasks) != 1 {
				t.Errorf("%v %+v", err, p)
				return
			}
			for j := range p.Tasks[0].Materials {
				m := &p.Tasks[0].Materials[j]
				m.Text = "mutated"
				if m.Bytes != nil {
					*m.Bytes = 999
				}
				if len(m.SourceIDs) > 0 {
					m.SourceIDs[0] = "mutated"
				}
			}
		}()
	}
	wg.Wait()
	if *r.Subjects[0].Materials[2].Bytes != before {
		t.Fatal("input byte measurement mutated")
	}
	for _, m := range r.Subjects[0].Materials {
		if m.Text == "mutated" || strings.Contains(strings.Join(m.Provenance.SourceIDs, ","), "mutated") {
			t.Fatal("input material mutated")
		}
	}
}
