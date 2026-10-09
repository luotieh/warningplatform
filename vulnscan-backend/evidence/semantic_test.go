package evidence

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type semanticModelFunc func(context.Context, SemanticCall) (string, error)

func (f semanticModelFunc) Complete(ctx context.Context, call SemanticCall) (string, error) {
	return f(ctx, call)
}

func semanticFixture(spec slotSpec) SemanticRequest {
	scope := Scope{AssetID: "asset", EndpointID: "endpoint", DeviceID: "device"}
	if spec.Key.ID == "BT-S01" || spec.Key.ID == "SC02" {
		scope = Scope{GroupID: "group"}
	}
	window := AnalysisWindow{time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)}
	s := SemanticSubject{ID: "subject", PropositionID: "operation", Scope: scope, Window: window}
	add := func(id, kind string) {
		for _, m := range s.Materials {
			if m.ID == id {
				return
			}
		}
		s.Materials = append(s.Materials, SemanticMaterial{ID: id, Kind: kind, Scope: scope, SnapshotVersion: 1, Window: window,
			Provenance: Provenance{Verified: true, Complete: true, Version: "parsed-1", SourceIDs: []string{"source-" + id}}, Text: "真实材料：" + id, FieldPath: "parsed." + id, Redacted: true,
			TransactionID: "txn", Direction: "outbound", Method: "POST", Protocol: "http", Destination: "https://example.test/submit", FieldNames: []string{"username"}, Role: "workstation"})
	}
	find := func(id string) *SemanticMaterial {
		for i := range s.Materials {
			if s.Materials[i].ID == id {
				return &s.Materials[i]
			}
		}
		panic(id)
	}
	for _, kind := range spec.Kinds {
		add(kind, kind)
	}
	// Every command/response fixture includes an actual verified pair.
	if spec.Key.ID == "S01" || spec.Key.ID == "S02" || spec.Key.ID == "S10" || (spec.Key.ID == "S13" && spec.Key.Subtype == "command") {
		add("protocol_request", "protocol_request")
		add("protocol_response", "protocol_response")
		add("pair", "pair")
		find("protocol_response").Direction = "inbound"
		find("pair").RelatedIDs = []string{"protocol_request", "protocol_response"}
	}
	if spec.Key.ID == "S11" {
		find("stratum_request").Method = "mining.subscribe"
		find("stratum_request").Text = `{"id":1,"method":"mining.subscribe","params":[]}`
		find("stratum_request").FieldNames = []string{"params"}
		find("stratum_response").Text = `{"id":1,"result":[],"error":null}`
		find("stratum_response").Direction = "inbound"
		find("pair").RelatedIDs = []string{"stratum_request", "stratum_response"}
	}
	if spec.Key.ID == "S04" || spec.Key.ID == "S13" {
		add("encoded_payload", "encoded_payload")
		find("decoded_payload").Text = "run_status"
		find("encoded_payload").Text = base64.StdEncoding.EncodeToString([]byte("run_status"))
		find("decode").DecodeSteps = []SemanticDecodeStep{{"base64", "encoded_payload", "decoded_payload"}}
		if spec.Key.ID == "S04" {
			find("domain").RelatedIDs = []string{"encoded_payload"}
		}
		if spec.Key.Subtype == "other" {
			find("operation_context").RelatedIDs = []string{"decoded_payload"}
		}
		if spec.Key.Subtype == "command" {
			find("protocol_request").RelatedIDs = []string{"decoded_payload"}
		}
	}
	if spec.Key.ID == "S05" || (spec.Key.ID == "S12" && spec.Key.Subtype == "brand_semantic_impostor") {
		add("brand_relation", "brand_relation")
		find("brand_relation").RelatedIDs = []string{"host", "brand_authorization"}
	}
	if spec.Key.ID == "S07" {
		n := uint64(512)
		find("volume").Bytes = &n
	}
	if spec.Key.ID == "S08" {
		add("chunk2", "chunk")
		add("volume2", "volume")
		one, two, bytes := uint64(1), uint64(2), uint64(512)
		find("chunk").Sequence, find("chunk").Bytes = &one, &bytes
		find("chunk2").Sequence, find("chunk2").Bytes, find("chunk2").TransactionID = &two, &bytes, "txn2"
		find("volume").Bytes = &bytes
		find("volume2").Bytes, find("volume2").TransactionID = &bytes, "txn2"
		find("transfer_join").RelatedIDs = []string{"chunk", "chunk2"}
	}
	if spec.Key.ID == "BT-S01" || spec.Key.ID == "SC02" {
		add("member2", "group_member")
		find("group_member").AssetID, find("group_member").Role = "asset1", "workstation"
		find("member2").AssetID, find("member2").Role = "asset2", "workstation"
	}
	if spec.Key.ID == "R06" || spec.Key.ID == "R07" {
		m := find("history")
		m.EventID, m.AdjudicationID, m.AdjudicationSource, m.FalsePositive = "old-event", "review-1", "human", true
	}
	fids := append(append([]FactID(nil), spec.AllFacts...), spec.AnyFacts...)
	if len(fids) == 0 {
		fids = []FactID{BeaconPeriodic}
	}
	for _, id := range fids {
		s.Facts = append(s.Facts, Finding{FactID: id, RuleVersion: RuleVersion, SnapshotVersion: 1, Scope: scope, Window: &Window{Start: window.Start, End: window.End}, Status: Observed, Eligibility: "eligible", SourceIDs: []string{"fact-source"}})
	}
	return SemanticRequest{EventID: "event", SnapshotVersion: 1, Subjects: []SemanticSubject{s}, Slots: []SlotKey{spec.Key}}
}

func semanticTestEngine(t *testing.T) *SemanticEngine {
	t.Helper()
	e, err := NewSemanticEngine(DefaultSemanticConfig())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func semanticResponse(call SemanticCall, mutate func(*SemanticItem)) string {
	var input struct {
		Tasks []SemanticTask `json:"tasks"`
	}
	if err := json.Unmarshal([]byte(call.Prompt), &input); err != nil {
		panic(err)
	}
	items := []SemanticItem{}
	for _, task := range input.Tasks {
		i := SemanticItem{TaskID: task.ID, Judgement: "support", Strength: task.MaxStrength, MaterialRefs: []string{}, FactRefs: []string{}, AdjudicationRefs: []string{}, Quotes: []SemanticQuote{}, Explanation: "根据引用解释可见行为，仍需人工核验。", Alternatives: []string{"可能为授权活动"}, Gaps: []string{"缺少主机侧结果"}}
		for _, m := range task.Materials {
			i.MaterialRefs = append(i.MaterialRefs, m.ID)
			i.Quotes = append(i.Quotes, SemanticQuote{m.ID, m.Text})
			if m.AdjudicationID != "" {
				i.AdjudicationRefs = append(i.AdjudicationRefs, m.AdjudicationID)
			}
		}
		for _, f := range task.Facts {
			i.FactRefs = append(i.FactRefs, f.ID)
		}
		if mutate != nil {
			mutate(&i)
		}
		items = append(items, i)
	}
	data, _ := json.Marshal(struct {
		Items []SemanticItem `json:"items"`
	}{items})
	return string(data)
}

func TestSemanticAll23Slots(t *testing.T) {
	if len(SemanticDefinitions()) != 23 {
		t.Fatal("wrong registry count")
	}
	explanations := 0
	for _, spec := range semanticSpecs {
		if spec.ExplanationOnly {
			explanations++
		}
		t.Run(spec.Key.String(), func(t *testing.T) {
			e := semanticTestEngine(t)
			r := semanticFixture(spec)
			calls := 0
			got, err := e.Evaluate(context.Background(), r, semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) {
				calls++
				if call.MaxOutputTokens != 2000 {
					t.Fatal("output token contract lost")
				}
				return semanticResponse(call, nil), nil
			}))
			if err != nil || calls != 1 || len(got.Findings) != 1 || got.Plan.Executions[0].Status != "accepted" {
				t.Fatalf("err=%v result=%+v", err, got)
			}
			if got.Findings[0].Slot != spec.Key || got.Findings[0].SnapshotVersion != 1 || got.Plan.InputBytes > 12000 || got.Plan.ContextSHA256 == "" {
				t.Fatal("trace/budget mismatch")
			}
		})
	}
	if explanations != 5 {
		t.Fatal("wrong explanation-only count")
	}
}

func TestSemanticEverySlotRejectsMissingAndUnverifiedMaterial(t *testing.T) {
	for _, spec := range semanticSpecs {
		for _, mode := range []string{"missing", "unverified"} {
			t.Run(spec.Key.String()+"/"+mode, func(t *testing.T) {
				r := semanticFixture(spec)
				if mode == "missing" {
					r.Subjects[0].Materials = nil
				} else {
					for i := range r.Subjects[0].Materials {
						r.Subjects[0].Materials[i].Provenance.Verified = false
					}
				}
				got, err := semanticTestEngine(t).Evaluate(context.Background(), r, semanticModelFunc(func(context.Context, SemanticCall) (string, error) {
					t.Fatal("ineligible task called model")
					return "", nil
				}))
				if err != nil || len(got.Plan.Tasks) != 0 || got.Calls != 0 || got.Plan.Executions[0].Status != "skipped" {
					t.Fatalf("err=%v result=%+v", err, got)
				}
			})
		}
	}
}

func TestSemanticAllSlotsRejectInventedReferences(t *testing.T) {
	for _, spec := range semanticSpecs {
		t.Run(spec.Key.String(), func(t *testing.T) {
			got, err := semanticTestEngine(t).Evaluate(context.Background(), semanticFixture(spec), semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) {
				return semanticResponse(call, func(i *SemanticItem) { i.MaterialRefs[0] = "invented-source" }), nil
			}))
			if err != nil || len(got.Findings) != 0 || got.Plan.Executions[0].Reason != "undelivered_or_missing_reference" {
				t.Fatalf("%v %+v", err, got)
			}
		})
	}
}

func TestSemanticResponseValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*SemanticItem)
		reason string
	}{
		{"invented_quote", func(i *SemanticItem) { i.Quotes[0].Excerpt = "不存在的原文" }, "non_verbatim_or_undelivered_quote"},
		{"missing_fact", func(i *SemanticItem) { i.FactRefs = []string{"F_FAKE"} }, "undelivered_or_missing_reference"},
		{"missing_quotes", func(i *SemanticItem) { i.Quotes = nil }, "missing_or_excessive_quotes"},
		{"invalid_judgement", func(i *SemanticItem) { i.Judgement = "malicious" }, "invalid_judgement"},
		{"neutral_strong", func(i *SemanticItem) { i.Judgement = "neutral" }, "invalid_or_excessive_strength"},
		{"probability_strength", func(i *SemanticItem) { i.Strength = "99%" }, "invalid_or_excessive_strength"},
		{"missing_response_quote", func(i *SemanticItem) { i.Quotes = []SemanticQuote{i.Quotes[0]} }, "strong_requires_paired_quotes"},
		{"secret_echo", func(i *SemanticItem) { i.Explanation = "password=secret" }, "sensitive_model_output"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := semanticTestEngine(t).Evaluate(context.Background(), semanticFixture(semanticSpecs[0]), semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) {
				return semanticResponse(call, c.mutate), nil
			}))
			if err != nil || len(got.Findings) != 0 || got.Plan.Executions[0].Reason != c.reason {
				t.Fatalf("%v %+v", err, got)
			}
		})
	}
}

func TestSemanticStrictJSON(t *testing.T) {
	responses := []string{`{"items":[],"items":[]}`, "```json\n{\"items\":[]}\n```", `{"items":[],"score":99}`, `{"items":[]} {}`, `null`, `{}`, `{"items":[{"task_id":"T001","score":9}]}`, `{"items":[{"task_id":"T001","task_id":"T002"}]}`, `{"items":[],"Items":[]}`}
	for _, raw := range responses {
		t.Run(raw, func(t *testing.T) {
			got, err := semanticTestEngine(t).Evaluate(context.Background(), semanticFixture(semanticSpecs[0]), semanticModelFunc(func(context.Context, SemanticCall) (string, error) { return raw, nil }))
			if err != nil || len(got.Findings) != 0 || got.Plan.Executions[0].Reason != "invalid_model_response" {
				t.Fatalf("%v %+v", err, got)
			}
		})
	}
}

func TestSemanticBindings(t *testing.T) {
	cases := []struct {
		name   string
		change func(*SemanticRequest)
	}{
		{"scope", func(r *SemanticRequest) { r.Subjects[0].Materials[0].Scope.AssetID = "other" }},
		{"snapshot", func(r *SemanticRequest) { r.Subjects[0].Materials[0].SnapshotVersion = 2 }},
		{"window", func(r *SemanticRequest) {
			r.Subjects[0].Materials[0].Window.End = r.Subjects[0].Window.End.Add(time.Hour)
		}},
		{"fact_scope", func(r *SemanticRequest) { r.Subjects[0].Facts[0].Scope.AssetID = "other" }},
		{"fact_snapshot", func(r *SemanticRequest) { r.Subjects[0].Facts[0].SnapshotVersion = 2 }},
		{"duplicate_material", func(r *SemanticRequest) {
			r.Subjects[0].Materials = append(r.Subjects[0].Materials, r.Subjects[0].Materials[0])
		}},
		{"duplicate_subject", func(r *SemanticRequest) { r.Subjects = append(r.Subjects, r.Subjects[0]) }},
		{"duplicate_slot", func(r *SemanticRequest) { r.Slots = append(r.Slots, r.Slots[0]) }},
		{"bare_ambiguous_id", func(r *SemanticRequest) { r.Slots = []SlotKey{{ID: "S12"}} }},
		{"unknown_slot", func(r *SemanticRequest) { r.Slots = []SlotKey{{ID: "S99", Target: "fake"}} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := semanticFixture(semanticSpecs[0])
			c.change(&r)
			if _, err := semanticTestEngine(t).Plan(context.Background(), r); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}

func TestSemanticPrerequisiteBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		slot   int
		change func(*SemanticSubject)
		reason string
	}{
		{"wrong_pair", 1, func(s *SemanticSubject) {
			for i := range s.Materials {
				if s.Materials[i].Kind == "protocol_response" {
					s.Materials[i].TransactionID = "other"
				}
			}
		}, "unresolved_bidirectional_pair"},
		{"missing_action", 5, func(s *SemanticSubject) {
			for i := range s.Facts {
				s.Facts[i].Status = NotObserved
			}
		}, "missing_observed_action_or_coordination_fact"},
		{"credential_join", 5, func(s *SemanticSubject) { s.Materials[0].TransactionID = "other" }, "unresolved_request_fields"},
		{"wrong_direction", 6, func(s *SemanticSubject) {
			for i := range s.Materials {
				if s.Materials[i].Kind == "protocol_request" {
					s.Materials[i].Direction = "inbound"
				}
			}
		}, "unresolved_complete_upload"},
		{"duplicate_chunk_sequence", 7, func(s *SemanticSubject) {
			for i := range s.Materials {
				if s.Materials[i].Kind == "chunk" {
					n := uint64(1)
					s.Materials[i].Sequence = &n
				}
			}
		}, "unresolved_chunk_sequence"},
		{"fake_decode", 3, func(s *SemanticSubject) {
			for i := range s.Materials {
				if s.Materials[i].Kind == "decoded_payload" {
					s.Materials[i].Text = "different"
				}
			}
		}, "invalid_decode_chain"},
		{"decoded_not_request", 13, func(s *SemanticSubject) {
			for i := range s.Materials {
				if s.Materials[i].Kind == "protocol_request" {
					s.Materials[i].RelatedIDs = nil
				}
			}
		}, "unresolved_decoded_request"},
		{"history_ai", 21, func(s *SemanticSubject) { s.Materials[0].AdjudicationSource = "llm" }, "invalid_independent_adjudication"},
		{"history_current", 21, func(s *SemanticSubject) { s.Materials[0].EventID = "event" }, "invalid_independent_adjudication"},
		{"not_reviewed_false_positive", 22, func(s *SemanticSubject) { s.Materials[0].FalsePositive = false }, "invalid_independent_adjudication"},
		{"duplicate_member", 17, func(s *SemanticSubject) {
			for i := range s.Materials {
				if s.Materials[i].Kind == "group_member" {
					s.Materials[i].AssetID = "same"
				}
			}
		}, "unresolved_group_members"},
		{"missing_hard_coordination", 17, func(s *SemanticSubject) {
			for i := range s.Facts {
				s.Facts[i].Status = Missing
			}
		}, "missing_observed_action_or_coordination_fact"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := semanticFixture(semanticSpecs[c.slot])
			c.change(&r.Subjects[0])
			p, err := semanticTestEngine(t).Plan(context.Background(), r)
			if err != nil || len(p.Tasks) != 0 || p.Executions[0].Reason != c.reason {
				t.Fatalf("%v %+v", err, p)
			}
		})
	}
}

func TestSemanticStrengthCaps(t *testing.T) {
	for _, mode := range []string{"unpaired_command", "clipped", "truncated", "brand_word_only", "domain_lexical", "explanation_only"} {
		t.Run(mode, func(t *testing.T) {
			slot := 0
			if mode == "brand_word_only" {
				slot = 12
			}
			if mode == "domain_lexical" {
				slot = 11
			}
			if mode == "explanation_only" {
				slot = 15
			}
			r := semanticFixture(semanticSpecs[slot])
			cfg := DefaultSemanticConfig()
			want := "weak"
			switch mode {
			case "unpaired_command":
				want = "medium"
				ms := []SemanticMaterial{}
				for _, m := range r.Subjects[0].Materials {
					if m.Kind != "pair" && m.Kind != "protocol_response" {
						ms = append(ms, m)
					}
				}
				r.Subjects[0].Materials = ms
			case "clipped":
				cfg.MaxMaterialBytes = 16
				r.Subjects[0].Materials[0].Text = strings.Repeat("真实", 50)
			case "truncated":
				r.Subjects[0].Materials[0].Truncated = true
			case "brand_word_only":
				r.Subjects[0].Materials = r.Subjects[0].Materials[:3]
			case "explanation_only":
				want = "none"
			}
			e, err := NewSemanticEngine(cfg)
			if err != nil {
				t.Fatal(err)
			}
			p, err := e.Plan(context.Background(), r)
			if err != nil || len(p.Tasks) != 1 || p.Tasks[0].MaxStrength != want {
				t.Fatalf("%v %+v", err, p)
			}
			got, err := e.Evaluate(context.Background(), r, semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) {
				return semanticResponse(call, func(i *SemanticItem) { i.Strength = "strong" }), nil
			}))
			if err != nil || len(got.Findings) != 0 || got.Plan.Executions[0].Reason != "invalid_or_excessive_strength" {
				t.Fatalf("%v %+v", err, got)
			}
		})
	}
}

func TestSemanticBudgetsAndSelection(t *testing.T) {
	r := semanticFixture(semanticSpecs[0])
	r.Slots = []SlotKey{semanticSpecs[0].Key, semanticSpecs[1].Key}
	cfg := DefaultSemanticConfig()
	cfg.MaxTasks = 1
	e, _ := NewSemanticEngine(cfg)
	p, err := e.Plan(context.Background(), r)
	if err != nil || len(p.Tasks) != 1 || p.Executions[1].Reason != "task_budget_exceeded" {
		t.Fatalf("%v %+v", err, p)
	}
	cfg = DefaultSemanticConfig()
	cfg.MaxInputBytes = len(semanticSystemPrompt) + 256
	e, _ = NewSemanticEngine(cfg)
	p, err = e.Plan(context.Background(), r)
	if err != nil || len(p.Tasks) != 0 || p.Executions[0].Reason != "context_budget_exceeded" {
		t.Fatalf("%v %+v", err, p)
	}
	cfg = DefaultSemanticConfig()
	cfg.MaxInputTokens = 10
	cfg.CountTokens = func(string, string) (int, error) { return 11, nil }
	e, _ = NewSemanticEngine(cfg)
	p, err = e.Plan(context.Background(), r)
	if err != nil || len(p.Tasks) != 0 {
		t.Fatalf("%v %+v", err, p)
	}
	r.Slots = []SlotKey{}
	p, err = semanticTestEngine(t).Plan(context.Background(), r)
	if err != nil || len(p.Tasks) != 0 || len(p.Executions) != 0 {
		t.Fatal("empty selection called model")
	}
	r.Slots = nil
	p, err = semanticTestEngine(t).Plan(context.Background(), r)
	if err != nil || len(p.Tasks) != 3 {
		t.Fatalf("auto applicability: %v %+v", err, p)
	} // S01, S02, S10
	r.Slots = []SlotKey{semanticSpecs[0].Key, semanticSpecs[1].Key}
	got, err := semanticTestEngine(t).Evaluate(context.Background(), r, semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) { return semanticResponse(call, nil), nil }))
	if err != nil || got.Calls != 1 || len(got.Findings) != 2 || got.Findings[1].DuplicateOf != got.Findings[0].TaskID {
		t.Fatalf("batch/dedupe: %v %+v", err, got)
	}
}

func TestSemanticUnavailableAndMalformedModel(t *testing.T) {
	r := semanticFixture(semanticSpecs[0])
	e := semanticTestEngine(t)
	got, err := e.Evaluate(context.Background(), r, nil)
	if err != nil || got.Calls != 0 || got.Plan.Executions[0].Reason != "model_unavailable" {
		t.Fatalf("%v %+v", err, got)
	}
	for _, mode := range []string{"error", "timeout", "missing_task", "invented_task", "duplicate_task", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			cfg := DefaultSemanticConfig()
			cfg.Timeout = time.Millisecond
			e, _ := NewSemanticEngine(cfg)
			got, err := e.Evaluate(context.Background(), r, semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) {
				switch mode {
				case "error":
					return "", errors.New("network")
				case "timeout":
					<-ctx.Done()
					return "", ctx.Err()
				case "missing_task":
					return `{"items":[]}`, nil
				case "invented_task":
					return semanticResponse(call, func(i *SemanticItem) { i.TaskID = "T999" }), nil
				case "duplicate_task":
					raw := semanticResponse(call, nil)
					var v struct {
						Items []SemanticItem `json:"items"`
					}
					json.Unmarshal([]byte(raw), &v)
					v.Items = append(v.Items, v.Items[0])
					b, _ := json.Marshal(v)
					return string(b), nil
				case "oversized":
					return strings.Repeat("x", cfg.MaxOutputBytes+1), nil
				}
				panic(mode)
			}))
			if err != nil || len(got.Findings) != 0 || got.Plan.Executions[0].Status == "accepted" {
				t.Fatalf("%v %+v", err, got)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Evaluate(ctx, r, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
}

func TestSemanticRedactionAndTrace(t *testing.T) {
	r := semanticFixture(semanticSpecs[0])
	r.Subjects[0].Materials[0].Text = `{"password":"raw-secret","token":"raw-token"} Authorization: Bearer raw-bearer`
	p, err := semanticTestEngine(t).Plan(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"raw-secret", "raw-token", "raw-bearer"} {
		if strings.Contains(p.Prompt, secret) {
			t.Fatal("secret leaked", secret)
		}
	}
	if !strings.Contains(p.Prompt, "REDACTED") || len(p.Tasks[0].Materials[0].SHA256) != 64 {
		t.Fatal("trace/redaction missing")
	}
	s := clipSemanticText(strings.Repeat("测", 10), 16)
	if !utf8.ValidString(s) || len(s) > 16 {
		t.Fatal("invalid UTF8 clipping")
	}
	r = semanticFixture(semanticSpecs[3])
	p, err = semanticTestEngine(t).Plan(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Prompt, base64.StdEncoding.EncodeToString([]byte("run_status"))) {
		t.Fatal("reversible encoded bytes leaked")
	}
}

func TestSemanticHistoryReferencesAndIndependentDedupe(t *testing.T) {
	r := semanticFixture(semanticSpecs[21])
	got, err := semanticTestEngine(t).Evaluate(context.Background(), r, semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) {
		return semanticResponse(call, func(i *SemanticItem) { i.AdjudicationRefs = nil }), nil
	}))
	if err != nil || len(got.Findings) != 0 || got.Plan.Executions[0].Reason != "undelivered_or_missing_reference" {
		t.Fatalf("%v %+v", err, got)
	}
	r = semanticFixture(semanticSpecs[0])
	other := semanticFixture(semanticSpecs[0]).Subjects[0]
	other.ID = "other"
	other.PropositionID = "independent-operation"
	r.Subjects = append(r.Subjects, other)
	got, err = semanticTestEngine(t).Evaluate(context.Background(), r, semanticModelFunc(func(ctx context.Context, call SemanticCall) (string, error) { return semanticResponse(call, nil), nil }))
	if err != nil || len(got.Findings) != 2 || got.Findings[1].DuplicateOf != "" {
		t.Fatalf("independent operations deduped: %v %+v", err, got)
	}
}
