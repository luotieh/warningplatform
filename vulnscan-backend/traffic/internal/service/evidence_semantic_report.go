package service

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/client"
)

type ReportSemanticOptions struct {
	Disable      bool
	InputMode    evidence.SemanticInputMode
	Config       evidence.SemanticConfig
	ModelVersion string
}

func DefaultReportSemanticOptions() ReportSemanticOptions {
	return ReportSemanticOptions{InputMode: evidence.SemanticRaw, Config: evidence.DefaultSemanticConfig()}
}

type ReportSemanticEvaluation struct {
	Status          string                     `json:"status"`
	Reason          string                     `json:"reason,omitempty"`
	InputMode       evidence.SemanticInputMode `json:"input_mode"`
	AdapterVersion  string                     `json:"adapter_version"`
	CacheHit        bool                       `json:"cache_hit"`
	ResultPersisted bool                       `json:"result_persisted"`
	ResultKey       string                     `json:"result_key,omitempty"`
	ElapsedMS       int64                      `json:"elapsed_ms"`
	Issues          []string                   `json:"issues,omitempty"`
	Result          *evidence.SemanticResult   `json:"result,omitempty"`
}

type cachedSemanticMaterials struct {
	AdapterVersion string                   `json:"adapter_version"`
	FactResultKey  string                   `json:"fact_result_key"`
	Request        evidence.SemanticRequest `json:"request"`
}

type ReportSemanticDiagnostics struct {
	EventID         string                       `json:"event_id"`
	SnapshotVersion int64                        `json:"snapshot_version"`
	At              time.Time                    `json:"at"`
	Status          string                       `json:"status"`
	Reason          string                       `json:"reason,omitempty"`
	InputMode       evidence.SemanticInputMode   `json:"input_mode"`
	AdapterVersion  string                       `json:"adapter_version"`
	ResultKey       string                       `json:"result_key,omitempty"`
	ResultPersisted bool                         `json:"result_persisted"`
	ElapsedMS       int64                        `json:"elapsed_ms"`
	CacheHit        bool                         `json:"cache_hit"`
	Issues          []string                     `json:"issues,omitempty"`
	Executions      []evidence.SemanticExecution `json:"executions,omitempty"`
	Summary         map[string]any               `json:"summary"`
}

func (s Services) prepareReportSemantics(ctx context.Context, snap EvidenceSnapshot, facts SnapshotFactEvaluation, factKey string, input *SnapshotEvidenceInput, persist bool, cacheAllowed bool, load func() (SnapshotEvidenceInput, error)) (out ReportSemanticEvaluation, err error) {
	start := time.Now()
	opts := DefaultReportSemanticOptions()
	if s.ReportSemantics != nil {
		opts = *s.ReportSemantics
	}
	out = ReportSemanticEvaluation{InputMode: opts.InputMode, AdapterVersion: semanticAdapterVersion, Status: "unavailable"}
	if opts.InputMode == "" {
		opts.InputMode = evidence.SemanticRedacted
		out.InputMode = opts.InputMode
	}
	if s.LLM != nil {
		copy := *s.LLM
		s.LLM = &copy
	}
	defer func() {
		out.ElapsedMS = time.Since(start).Milliseconds()
		if !persist {
			return
		}
		summary := reportSemanticSummary(out)
		delete(summary, "findings")
		d := ReportSemanticDiagnostics{EventID: snap.EventID, SnapshotVersion: snap.Version, At: time.Now().UTC(), Status: out.Status, Reason: out.Reason, InputMode: out.InputMode, AdapterVersion: out.AdapterVersion, ResultKey: out.ResultKey, ResultPersisted: out.ResultPersisted, ElapsedMS: out.ElapsedMS, CacheHit: out.CacheHit, Summary: summary}
		if out.Result != nil {
			d.Executions = out.Result.Plan.Executions
		}
		d.Issues = out.Issues
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if saveErr := putRecord(writeCtx, s.Store, "semantic_diagnostics", snapshotKey(snap.EventID, snap.Version), snap.EventID, d); saveErr != nil {
			log.Printf("[evidence] semantic_diagnostics_write_failed event=%s snapshot=%d", snap.EventID, snap.Version)
		}
	}()
	if opts.Disable {
		out.Status, out.Reason = "disabled", "semantic_execution_disabled"
		return out, nil
	}
	if facts.Status != "evaluated" || facts.Result == nil {
		out.Reason = "fact_inputs_unavailable"
		return out, nil
	}
	engine, err := evidence.NewSemanticEngine(opts.Config)
	if err != nil {
		out.Reason = "semantic_config_invalid"
		return out, nil
	}
	// CountTokens is executable code, never JSON/cache identity. Actual budget
	// values and the plan's actual prompt hash distinguish tokenizer results.
	budget := []any{opts.Config.MaxTasks, opts.Config.MaxInputBytes, opts.Config.MaxMaterialBytes, opts.Config.MaxOutputBytes, opts.Config.MaxOutputTokens, opts.Config.MaxInputTokens, opts.Config.Timeout.Milliseconds()}
	materialKey := digest([]any{factKey, semanticAdapterVersion, opts.InputMode})
	var request evidence.SemanticRequest
	materialCached := false
	if persist && cacheAllowed {
		record, exists, readErr := s.Store.AggregateRecord(ctx, "semantic_materials", materialKey)
		if readErr == nil && exists && len(record.Value) <= 8<<20 {
			var cached cachedSemanticMaterials
			if json.Unmarshal(record.Value, &cached) == nil && cached.AdapterVersion == semanticAdapterVersion && cached.FactResultKey == factKey && cached.Request.EventID == snap.EventID && cached.Request.SnapshotVersion == snap.Version && cached.Request.InputMode == opts.InputMode {
				request = cached.Request
				materialCached = true
			}
		}
		if readErr != nil {
			out.Issues = append(out.Issues, "semantic_materials_read_failed")
		} else if exists && !materialCached {
			out.Issues = append(out.Issues, "semantic_materials_cache_invalid")
		}
	}
	if !materialCached {
		if input == nil {
			loaded, loadErr := load()
			if loadErr != nil || loaded.Reason != "" {
				out.Reason = "semantic_inputs_unavailable"
				return out, nil
			}
			input = &loaded
		}
		request = buildSnapshotSemanticRequest(snap, *input, facts.Result, opts.InputMode)
		// Facts are already stored under factKey; avoid duplicating potentially
		// enormous fact provenance once per operation in the materials journal.
		if persist && cacheAllowed {
			cached := request
			cached.Subjects = append([]evidence.SemanticSubject(nil), request.Subjects...)
			for n := range cached.Subjects {
				cached.Subjects[n].Facts = nil
			}
			bundle := cachedSemanticMaterials{AdapterVersion: semanticAdapterVersion, FactResultKey: factKey, Request: cached}
			if raw, marshalErr := json.Marshal(bundle); marshalErr == nil && len(raw) <= 8<<20 {
				if saveErr := putRecord(ctx, s.Store, "semantic_materials", materialKey, snap.EventID, bundle); saveErr != nil {
					out.Issues = append(out.Issues, "semantic_materials_write_failed")
					log.Printf("[evidence] semantic_materials_write_failed event=%s snapshot=%d", snap.EventID, snap.Version)
				}
			}
		}
	}
	if materialCached {
		for n := range request.Subjects {
			subject := &request.Subjects[n]
			for _, f := range facts.Result.Findings {
				if f.Scope == subject.Scope && f.Window != nil && f.Window.Start.Equal(subject.Window.Start) && f.Window.End.Equal(subject.Window.End) {
					subject.Facts = append(subject.Facts, f)
				}
			}
		}
	}
	plan, err := engine.Plan(ctx, request)
	if err != nil && materialCached && ctx.Err() == nil {
		out.Issues = append(out.Issues, "semantic_materials_binding_invalid_rebuilt")
		if input == nil {
			loaded, loadErr := load()
			if loadErr != nil || loaded.Reason != "" {
				out.Reason = "semantic_inputs_unavailable"
				return out, nil
			}
			input = &loaded
		}
		request = buildSnapshotSemanticRequest(snap, *input, facts.Result, opts.InputMode)
		plan, err = engine.Plan(ctx, request)
		if err == nil && persist && cacheAllowed {
			cached := request
			cached.Subjects = append([]evidence.SemanticSubject(nil), request.Subjects...)
			for n := range cached.Subjects {
				cached.Subjects[n].Facts = nil
			}
			bundle := cachedSemanticMaterials{AdapterVersion: semanticAdapterVersion, FactResultKey: factKey, Request: cached}
			if raw, e := json.Marshal(bundle); e == nil && len(raw) <= 8<<20 {
				if e = putRecord(ctx, s.Store, "semantic_materials", materialKey, snap.EventID, bundle); e != nil {
					out.Issues = append(out.Issues, "semantic_materials_write_failed")
				}
			}
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		out.Reason = "semantic_material_binding_invalid"
		return out, nil
	}
	out.ResultKey = digest([]any{materialKey, evidence.SemanticVersion, budget, plan.ContextSHA256, plan.InputTokens, semanticModelIdentity(s), opts.ModelVersion, request.Slots})
	if persist && cacheAllowed {
		record, exists, readErr := s.Store.AggregateRecord(ctx, "semantic_result", out.ResultKey)
		if readErr == nil && exists && len(record.Value) <= 8<<20 {
			var cached ReportSemanticEvaluation
			if json.Unmarshal(record.Value, &cached) == nil && cached.AdapterVersion == semanticAdapterVersion && cached.InputMode == opts.InputMode && cached.Result != nil && cached.Result.Plan.RuleVersion == evidence.SemanticVersion && cached.Result.Plan.ContextSHA256 == plan.ContextSHA256 && cached.Result.Plan.EventID == snap.EventID && cached.Result.Plan.SnapshotVersion == snap.Version && semanticReusable(*cached.Result) && evidence.ValidateSemanticResult(plan, *cached.Result) == nil {
				cached.CacheHit = true
				cached.Issues = append(cached.Issues, out.Issues...)
				cached.ElapsedMS = time.Since(start).Milliseconds()
				return cached, nil
			}
		}
		if readErr != nil {
			out.Issues = append(out.Issues, "semantic_result_read_failed")
		} else if exists {
			out.Issues = append(out.Issues, "semantic_result_cache_invalid")
		}
	}
	var model evidence.SemanticModel
	if persist {
		model = s.SemanticModel
		if model == nil && s.LLM != nil {
			model = client.EvidenceSemanticModel{Client: *s.LLM}
		}
	}
	var result evidence.SemanticResult
	if !persist {
		result = evidence.SemanticResult{Plan: plan, Findings: []evidence.SemanticFinding{}}
		out.Status = "planned"
		out.Reason = "read_only_no_model_call"
	} else {
		result, err = engine.Evaluate(ctx, request, model)
		if err != nil {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			out.Reason = "semantic_execution_failed"
			return out, nil
		}
		out.Status = "evaluated"
		if len(result.Plan.Tasks) == 0 {
			out.Status = "no_applicable_tasks"
		} else {
			accepted, rejected, unavailable := 0, 0, 0
			for _, x := range result.Plan.Executions {
				switch x.Status {
				case "accepted":
					accepted++
				case "rejected":
					rejected++
				case "unavailable":
					unavailable++
				}
			}
			if accepted == 0 && rejected > 0 {
				out.Status, out.Reason = "rejected", "semantic_response_rejected"
			} else if accepted == 0 && unavailable > 0 {
				out.Status, out.Reason = "unavailable", "semantic_model_unavailable_or_failed"
			} else if rejected+unavailable > 0 {
				out.Status, out.Reason = "partial", "some_semantic_tasks_unavailable_or_rejected"
			}
		}
	}
	out.Result = &result
	out.ElapsedMS = time.Since(start).Milliseconds()
	if persist && cacheAllowed && semanticReusable(result) {
		out.ResultPersisted = true
		if raw, marshalErr := json.Marshal(out); marshalErr != nil || len(raw) > 8<<20 {
			out.ResultPersisted = false
			out.Reason = "semantic_result_budget_exceeded"
		} else if saveErr := putRecord(ctx, s.Store, "semantic_result", out.ResultKey, snap.EventID, out); saveErr != nil {
			out.ResultPersisted = false
			out.Reason = "semantic_result_write_failed"
		}
	}
	return out, nil
}

func semanticModelIdentity(s Services) any {
	if s.LLM == nil {
		return []any{"unconfigured", s.SemanticModel != nil}
	}
	return []any{strings.TrimRight(s.LLM.BaseURL, "/"), s.LLM.Model, s.LLM.Temperature, s.LLM.DisableThinking, digest(s.LLM.APIKey), s.SemanticModel != nil}
}

func semanticReusable(result evidence.SemanticResult) bool {
	for _, x := range result.Plan.Executions {
		if x.TaskID != "" && x.Status != "accepted" {
			return false
		}
	}
	return true
}

func reportSemanticSummary(e ReportSemanticEvaluation) map[string]any {
	out := map[string]any{"status": e.Status, "reason": e.Reason, "input_mode": e.InputMode, "cache_hit": e.CacheHit, "note": "语义结果为模型解释，不能修改事实状态、重算统计或证明攻击成功；解释强度不是威胁概率。"}
	counts := map[string]int{}
	reasons := map[string]int{}
	prerequisites, budget, unavailable, rejected := 0, 0, 0, 0
	entries := []map[string]any{}
	if e.Result != nil {
		for _, x := range e.Result.Plan.Executions {
			counts[x.Status]++
			reasons[x.Reason]++
			switch {
			case x.Reason == "task_budget_exceeded" || x.Reason == "context_budget_exceeded":
				budget++
			case x.Status == "skipped":
				prerequisites++
			case x.Status == "unavailable":
				unavailable++
			case x.Status == "rejected":
				rejected++
			}
		}
		for _, f := range e.Result.Findings {
			if f.DuplicateOf != "" {
				continue
			}
			quotes := []map[string]any{}
			for _, q := range f.Quotes[:min(2, len(f.Quotes))] {
				kind, path := "", ""
				for _, task := range e.Result.Plan.Tasks {
					if task.ID == f.TaskID {
						for _, m := range task.Materials {
							if m.ID == q.MaterialID {
								kind, path = m.Kind, m.FieldPath
							}
						}
					}
				}
				quotes = append(quotes, map[string]any{"kind": kind, "field_path": path, "excerpt": semanticSummaryText(q.Excerpt, 96), "excerpt_clipped": utf8.RuneCountInString(q.Excerpt) > 96})
			}
			entries = append(entries, map[string]any{"slot": f.Slot, "scope": f.Scope, "window": f.Window, "judgement": f.Judgement, "strength": f.Strength, "explanation": semanticSummaryText(f.Explanation, 200), "quotes": quotes, "omitted_quotes": len(f.Quotes) - len(quotes), "alternatives": semanticSummaryStrings(f.Alternatives), "gaps": semanticSummaryStrings(f.Gaps), "projection_compacted": true, "explanation_only": f.ExplanationOnly, "non_additive_with": f.NonAdditiveWith})
		}
		out["calls"], out["tasks"], out["input_bytes"] = e.Result.Calls, len(e.Result.Plan.Tasks), e.Result.Plan.InputBytes
	}
	out["execution_counts"], out["missing_prerequisites"], out["budget_not_executed"], out["unavailable"], out["rejected"] = counts, prerequisites, budget, unavailable, rejected
	// Exact reasons remain in the persisted plan; avoid a giant missing-kind
	// dictionary crowding the final report. Retain the most frequent reasons.
	keys := []string{}
	for k := range reasons {
		keys = append(keys, k)
	}
	sortSemanticReasonKeys(keys, reasons)
	top := map[string]int{}
	for _, k := range keys[:min(4, len(keys))] {
		top[k] = reasons[k]
	}
	out["reason_summary"] = top
	out["total_findings"] = len(entries)
	if len(entries) > 4 {
		entries = entries[:4]
	}
	for {
		out["findings"], out["omitted_findings"] = entries, out["total_findings"].(int)-len(entries)
		raw, _ := json.Marshal(out)
		if utf8.RuneCount(raw) <= 1800 || len(entries) == 0 {
			break
		}
		entries = entries[:len(entries)-1]
	}
	return out
}

// Only display projection is shortened; validated full findings stay in the
// independent journal. Quote prefixes remain exact substrings without ellipses.
func semanticSummaryText(s string, max int) string {
	r := []rune(s)
	return string(r[:min(max, len(r))])
}

func semanticSummaryStrings(ss []string) []string {
	out := []string{}
	for _, s := range ss[:min(2, len(ss))] {
		out = append(out, semanticSummaryText(s, 96))
	}
	return out
}

func sortSemanticReasonKeys(keys []string, reasons map[string]int) {
	sort.Slice(keys, func(i, j int) bool {
		if reasons[keys[i]] == reasons[keys[j]] {
			return keys[i] < keys[j]
		}
		return reasons[keys[i]] > reasons[keys[j]]
	})
}
