package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/config"
)

type reportLogContextKey struct{}
type reportLog struct {
	mu           sync.Mutex
	dir          string
	meta         map[string]any
	errors       int
	call         int
	semantic     int
	semanticWire int
}

var reportLogSegment = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func beginReportLog(ctx context.Context, eventID, kind string, version int, o config.ReportOptions) (context.Context, *reportLog) {
	if o.LogDir == "" {
		o.LogDir = "data/repLogs"
	}
	r := &reportLog{meta: map[string]any{"event_id": eventID, "entry_kind": kind, "analysis_version": version, "build_revision": ReportBuildRevision, "status": "running", "started_at": time.Now().UTC(), "capacity": o, "capacity_verified": false}}
	if o.LogEnabled != nil && !*o.LogEnabled {
		return context.WithValue(ctx, reportLogContextKey{}, r), r
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		r.errors++
		log.Printf("[repLogs] run_id_failed event=%s", eventID)
		return context.WithValue(ctx, reportLogContextKey{}, r), r
	}
	id := hex.EncodeToString(b)
	r.meta["report_run_id"] = id
	root, err := filepath.Abs(o.LogDir)
	if err != nil {
		r.errors++
		return context.WithValue(ctx, reportLogContextKey{}, r), r
	}
	date := time.Now().In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01-02")
	r.dir = filepath.Join(root, date, reportLogSegment.ReplaceAllString(eventID, "_"), id)
	if err = os.MkdirAll(r.dir, 0700); err != nil {
		r.errors++
		r.dir = ""
		log.Printf("[repLogs] directory_unavailable event=%s", eventID)
	}
	if r.dir != "" {
		if err = reportAtomicWrite(filepath.Join(root, ".repLogs-root"), []byte("report-logs-v1\n")); err != nil {
			r.errors++
			log.Printf("[repLogs] root_marker_write_failed")
		}
	}
	r.write("manifest.json", r.meta)
	return context.WithValue(ctx, reportLogContextKey{}, r), r
}
func reportLogFrom(ctx context.Context) *reportLog {
	r, _ := ctx.Value(reportLogContextKey{}).(*reportLog)
	return r
}
func (r *reportLog) write(name string, value any) {
	if r == nil || r.dir == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err == nil {
		err = reportAtomicWrite(filepath.Join(r.dir, name), append(raw, '\n'))
	}
	if err != nil {
		r.errors++
		log.Printf("[repLogs] write_failed run=%s file=%s", r.meta["report_run_id"], name)
	}
}
func reportAtomicWrite(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".writing-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func (r *reportLog) finish(err error) {
	if r == nil {
		return
	}
	r.meta["finished_at"] = time.Now().UTC()
	r.meta["status"] = "success"
	if err != nil {
		r.meta["status"] = "failed"
		r.meta["failure"] = analysisFailureSummary(err.Error())
	}
	r.meta["log_write_errors"] = r.errors
	r.meta["log_complete"] = r.errors == 0 && r.dir != ""
	r.write("manifest.json", r.meta)
	if r.dir != "" {
		text := fmt.Sprintf("# 报告任务记录\n\n事件：%v\n任务：%v\n状态：%v\n快照：%v\n版本：%v\n日志写入错误：%d\n\n概率为证据约束的模型估计；实际支持依据、反向依据、概率及发布结果见 probability-publication.json。\n缺失阶段不代表成功；证据可用数与条目原因见 material-coverage.json；最终收到的内容见 llm-call-*-request.json。\n", r.meta["event_id"], r.meta["report_run_id"], r.meta["status"], r.meta["snapshot_version"], r.meta["analysis_version"], r.errors)
		counts, _ := json.MarshalIndent(r.meta["evidence_counts"], "", "  ")
		text += "\n数量口径（类型数与实例数分别记录）：\n\n```json\n" + string(counts) + "\n```\n"
		text += fmt.Sprintf("\n本次调用的实际概率：%v；模型提供的依据：%v。是否发布仍以 probability-publication.json 为准。\n", r.meta["probability"], r.meta["probability_reason"])
		if e := reportAtomicWrite(filepath.Join(r.dir, "summary.md"), []byte(text)); e != nil {
			log.Printf("[repLogs] summary_write_failed")
		}
	}
}
func (r *reportLog) observe(stage string, value any) {
	if r == nil {
		return
	}
	if stage == "request" {
		r.call++
		if v, ok := value.(map[string]any); ok {
			if payload, ok := v["payload"].(map[string]any); ok {
				text := ""
				if messages, ok := payload["messages"].([]map[string]string); ok {
					for _, m := range messages {
						text += m["content"]
					}
				}
				if instructions, ok := payload["instructions"].(string); ok {
					text += instructions
				}
				if input, ok := payload["input"].([]any); ok {
					for _, x := range input {
						if m, ok := x.(map[string]any); ok {
							if content, ok := m["content"].([]any); ok {
								for _, c := range content {
									if c, ok := c.(map[string]string); ok {
										text += c["text"]
									}
								}
							}
						}
					}
				}
				v["estimated_input_tokens"] = estimateTokens(text) + 12
				v["estimate_method"] = "existing CJK estimator plus 12 message overhead; actual usage is separate"
			}
		}
	}
	r.write(fmt.Sprintf("llm-call-%02d-%s.json", r.call, stage), value)
}

func (r *reportLog) observeSemantic(stage string, value any) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if stage == "request" {
		r.semanticWire++
	}
	n := r.semanticWire
	r.mu.Unlock()
	r.write(fmt.Sprintf("semantic-wire-%02d-%s.json", n, stage), value)
}
func (r *reportLog) prepared(p preparedReportInput) {
	if r == nil {
		return
	}
	r.meta["snapshot_version"] = p.Evidence.SnapshotVersion
	r.meta["evidence_counts"] = map[string]any{"fact_catalog": len(evidence.Definitions()), "semantic_slot_catalog": len(evidence.SemanticDefinitions()), "normalized_instances": len(p.Evidence.Normalized.Items), "report_entries": len(p.Evidence.Entries), "selected_report_entries": len(p.Evidence.SelectedIDs), "fact_status_counts": p.Evidence.FactCounts, "semantic_execution_counts": p.Evidence.SemanticCounts}
	r.write("evidence-before.json", map[string]any{"facts": p.Evaluation, "semantics": p.Semantics})
	r.write("evidence-normalized.json", p.Evidence.Normalized)
	essence := reportEssenceFor(p.Evidence)
	r.write("evidence-essence.json", map[string]any{"version": essence.Version, "items": essence.Items, "details": essence.Details})
	r.write("evidence-essence-trace.json", map[string]any{"trace": essence.Trace, "original_entry_file": "evidence-selection.json", "catalog_adapters": reportEssenceAdapters(p.Evidence)})
	r.meta["essence_count"] = len(essence.Items)
	selected := map[string]bool{}
	for _, id := range p.Evidence.SelectedIDs {
		selected[id] = true
	}
	rows := []map[string]any{}
	for _, e := range p.Evidence.Entries {
		reason := "retained_for_model"
		if !selected[e.ID] {
			reason = reportSelectionReason(e, p.Evidence)
		}
		rows = append(rows, map[string]any{"entry": e, "selected": selected[e.ID], "selection_reason": reason})
	}
	r.write("evidence-selection.json", map[string]any{"entries": rows, "selected_ids": p.Evidence.SelectedIDs, "digest": p.Evidence.Digest, "selection_omitted": p.Evidence.SelectionOmitted})
	if p.Evidence.Scoring != nil {
		r.write("evidence-weights.json", p.Evidence.Scoring)
		r.write("material-coverage.json", reportAvailability(p))
		return
	}
	policy := reportWeightPolicy(p.Evidence)
	weights := []map[string]any{}
	for _, e := range p.Evidence.Entries {
		influence := 1.0
		group := e.Family
		var rule any = "ordinary_relative_influence; not arithmetic probability points"
		for _, w := range policy["enhanced_temporal"].([]map[string]any) {
			if w["evidence_id"] == e.ID {
				influence = w["relative_influence"].(float64)
				group = w["dependency_group"].(string)
				rule = w["rule"]
			}
		}
		weights = append(weights, map[string]any{"evidence_id": e.ID, "kind": e.Kind, "family": e.Family, "source_ids": e.SourceIDs, "normalized": e.Unified, "selected": selected[e.ID], "relative_influence": influence, "dependency_group": group, "rule": rule, "role": e.Status})
	}
	r.write("evidence-weights.json", map[string]any{"model_evidence": essence.Items, "policy": policy, "items": weights, "calibrated_formula": false, "probability_process": "actual evidence and relative influence -> model cited rationale -> JSON/probability parsing -> publication; hidden model computation is unavailable"})
	r.write("material-coverage.json", reportAvailability(p))
}
func reportSelectionReason(e ReportEvidence, b ReportEvidenceBundle) string {
	if e.Kind == "semantic" && e.Semantic != nil {
		if e.Semantic.DuplicateOf != "" {
			return "upstream_duplicate"
		}
		if e.Semantic.ExplanationOnly {
			return "context_interpretation_not_independent_evidence"
		}
	}
	if e.Status == "missing" || e.Status == "unavailable" {
		return "input_or_execution_unavailable"
	}
	if strings.HasPrefix(e.Family, "saved_packet:") {
		return "raw_packet_in_technical_appendix"
	}
	if e.Semantic != nil && e.Semantic.Judgement == "neutral" {
		return "neutral_semantic_not_independent_evidence"
	}
	if e.FactID == "F_MULTI_DAY_PERSIST" && e.Status == "not_observed" {
		return "short_current_window_cannot_refute_history"
	}
	if e.Status == "not_observed" {
		return "negative_rule_not_relevant_to_current_event"
	}
	return "excluded_by_existing_report_projection; inspect entry and digest (no new selection policy)"
}
func reportAvailability(p preparedReportInput) map[string]any {
	facts := []map[string]any{}
	complete := map[string]bool{}
	gapFree := map[string]bool{}
	reasons := map[string]int{}
	for _, row := range p.Evaluation.Manifest.FactCoverage {
		done := row.Status == "observed" || row.Status == "not_observed"
		quality, eligibility := "unknown", "unknown"
		for _, f := range p.Evidence.FactChecks {
			if f.FactID == row.FactID && f.Scope == row.Scope {
				quality, eligibility = f.Quality, f.Eligibility
				break
			}
		}
		usable := done && quality == "complete" && eligibility == "eligible"
		if usable {
			gapFree[string(row.FactID)] = true
		}
		if done {
			complete[string(row.FactID)] = true
		}
		reasons[string(row.Reason)]++
		facts = append(facts, map[string]any{"execution": row, "completed": done, "gap_free_completed": usable, "quality": quality, "eligibility": eligibility, "applicability": "not independently established; missing does not mean not applicable", "required_inputs": evidence.FactInputs(row.FactID)})
	}
	slots := map[string]bool{}
	gapFreeSlots := map[string]bool{}
	if p.Semantics.Result != nil {
		for _, x := range p.Semantics.Result.Plan.Executions {
			if x.Status == "accepted" {
				slots[x.Slot.String()] = true
			}
		}
		for _, f := range p.Semantics.Result.Findings {
			if !slots[f.Slot.String()] || len(f.Gaps) > 0 || f.DuplicateOf != "" {
				continue
			}
			for _, task := range p.Semantics.Result.Plan.Tasks {
				if task.ID != f.TaskID {
					continue
				}
				completeMaterials := len(task.Materials) > 0
				for _, m := range task.Materials {
					if m.Truncated {
						completeMaterials = false
					}
				}
				if completeMaterials {
					gapFreeSlots[f.Slot.String()] = true
				}
			}
		}
	}
	return map[string]any{"manifest": p.Evaluation.Manifest, "fact_catalog": evidence.Definitions(), "semantic_catalog": evidence.SemanticDependencyDefinitions(), "facts": facts, "completed_fact_type_count": len(complete), "completed_fact_ids": complete, "gap_free_fact_type_count": len(gapFree), "gap_free_fact_ids": gapFree, "validated_semantic_slot_type_count": len(slots), "validated_semantic_slot_ids": slots, "gap_free_semantic_slot_type_count": len(gapFreeSlots), "gap_free_semantic_slot_ids": gapFreeSlots, "semantic_execution_status": p.Semantics.Status, "semantics": p.Semantics, "reason_counts": reasons, "practical_observations": p.Evaluation.Manifest.ReportPractical, "practical_checks": p.Evaluation.Manifest.ReportPracticalChecks, "count_scope": "this actual snapshot; accepted semantics and computed facts, not a global availability claim; gap_free facts additionally require complete quality and eligible; partial history remains a qualified lower-bound fact; gap_free semantics require accepted nonduplicate findings without declared gaps and without truncated task materials"}
}

// Explicit maintenance operation: only marked, completed runs inside the log
// hierarchy; never symlinks or running tasks. No report-path recursive deletion.
func PruneReportLogs(root string, days int, now time.Time) (int, error) {
	if days <= 0 || strings.TrimSpace(root) == "" {
		return 0, fmt.Errorf("positive retention required")
	}
	base, err := filepath.Abs(root)
	if err != nil {
		return 0, err
	}
	marker, e := os.ReadFile(filepath.Join(base, ".repLogs-root"))
	if e != nil || string(marker) != "report-logs-v1\n" {
		return 0, fmt.Errorf("report_log_root_marker_missing")
	}
	base, e = filepath.EvalSymlinks(base)
	if e != nil {
		return 0, e
	}
	count := 0
	err = filepath.WalkDir(base, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.Name() != "manifest.json" {
			return nil
		}
		rel, e := filepath.Rel(base, path)
		if e != nil {
			return e
		}
		// expected date/event/run/manifest depth
		if len(regexp.MustCompile(`[\\/]`).Split(rel, -1)) != 4 {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var m struct {
			Status   string    `json:"status"`
			Finished time.Time `json:"finished_at"`
		}
		if json.Unmarshal(raw, &m) != nil || m.Finished.IsZero() || m.Status == "running" || now.Sub(m.Finished) < time.Duration(days)*24*time.Hour {
			return nil
		}
		if m.Status != "success" && m.Status != "failed" {
			return nil
		}
		target, e := filepath.EvalSymlinks(filepath.Dir(path))
		if e != nil {
			return e
		}
		checked, e := filepath.Rel(base, target)
		if e != nil || checked == "." || checked == ".." || strings.HasPrefix(checked, ".."+string(filepath.Separator)) {
			return fmt.Errorf("report_log_cleanup_outside_root")
		}
		if e = os.RemoveAll(target); e != nil {
			return e
		}
		count++
		return nil
	})
	return count, err
}
