package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

const EvidencePipelineVersion = "evidence-pipeline-2.1"

// EvidencePipeline owns the formal report preparation path. It delegates to the
// existing adapters, engines and report normalizer; it is not another engine.
type EvidencePipeline struct{ Services Services }
type EvidencePipelineOptions struct{ Persist bool }

type PipelineCheck struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Status    string         `json:"status"`
	Reason    string         `json:"reason,omitempty"`
	Instances int            `json:"instances"`
	States    map[string]int `json:"instance_states"`
	Reasons   map[string]int `json:"instance_reasons,omitempty"`
}

type EvidencePipelineAudit struct {
	CatalogTotal         int                     `json:"catalog_total"`
	CatalogTerminalCount int                     `json:"catalog_terminal_count"`
	ExecutedInstances    int                     `json:"executed_instances"`
	AcceptedInstances    int                     `json:"accepted_instances"`
	SemanticSummary      PipelineSemanticSummary `json:"semantic_summary"`
	Metrics              EvidencePipelineMetrics `json:"metrics"`
	Version              string                  `json:"version"`
	ExpectedFacts        int                     `json:"expected_facts"`
	ExpectedSemantics    int                     `json:"expected_semantic_slots"`
	Total                int                     `json:"total"`
	Completed            int                     `json:"completed"`
	Key                  string                  `json:"key"`
	EventID              string                  `json:"event_id"`
	SnapshotVersion      int64                   `json:"snapshot_version"`
	Watermark            int64                   `json:"watermark"`
	RevisionWatermark    int64                   `json:"revision_watermark"`
	RuleVersion          string                  `json:"rule_version"`
	SemanticVersion      string                  `json:"semantic_version"`
	NormalizationVersion string                  `json:"normalization_version"`
	Checks               []PipelineCheck         `json:"checks"`
	Counts               map[string]int          `json:"counts"`
	ElapsedMS            int64                   `json:"elapsed_ms"`
	Persisted            bool                    `json:"persisted"`
	Issues               []string                `json:"issues,omitempty"`
}

type PipelineSemanticSummary struct {
	Accepted                 int `json:"semantic_tasks_accepted"`
	Neutral                  int `json:"semantic_neutral"`
	Support                  int `json:"semantic_support"`
	Contradict               int `json:"semantic_contradict"`
	ExplanationOnly          int `json:"semantic_explanation_only"`
	MaliciousSupportEligible int `json:"malicious_support_eligible"`
}

// Execute uses the same path as report generation. Persist=false also disables
// model execution and all cache writes, for isolated/offline verification.
func (p EvidencePipeline) Execute(ctx context.Context, eventID string, options EvidencePipelineOptions) (preparedReportInput, error) {
	event, ok := p.Services.Store.GetEvent(eventID)
	if !ok {
		return preparedReportInput{}, fmt.Errorf("event_not_found")
	}
	return p.executeEvent(ctx, event, options)
}

func (p EvidencePipeline) executeEvent(ctx context.Context, event domain.Event, options EvidencePipelineOptions) (preparedReportInput, error) {
	limits := p.Services.pipelineLimits()
	ctx = context.WithValue(ctx, pipelineLimitsKey{}, limits)
	ctx, cancel := context.WithTimeout(ctx, limits.TotalTimeout)
	defer cancel()
	start := time.Now()
	metrics := EvidencePipelineMetrics{StageMS: map[string]int64{}, CacheHits: map[string]int{}}
	ctx = context.WithValue(ctx, pipelineMetricsKey{}, &metrics)
	prepared, err := p.Services.executeEvidencePipeline(ctx, event, options.Persist)
	if err != nil {
		return prepared, err
	}
	audit := pipelineAudit(event.EventID, prepared.Evaluation, prepared.Semantics)
	if prepared.Semantics.Result != nil && !prepared.Semantics.CacheHit {
		metrics.SemanticModelCalls = prepared.Semantics.Result.Calls
	}
	audit.Metrics = metrics
	audit.ElapsedMS = time.Since(start).Milliseconds()
	var joint any
	if prepared.Evidence.PhaseOne != nil {
		joint = prepared.Evidence.PhaseOne.Result
	}
	audit.Key = digest([]any{EvidencePipelineVersion, event.EventID, audit.SnapshotVersion, audit.Watermark, audit.RevisionWatermark, prepared.Evidence.Normalized, joint, prepared.Semantics.ResultKey})
	if options.Persist {
		audit.Persisted = true
		// Keep the complete normalization, source graph and C result in the
		// existing journal. Only the bounded counts/key go into the model input.
		journal := pipelineJournal{Audit: audit, Evidence: prepared.Evidence}
		if e := p.Services.persistPipelineJournal(ctx, audit.Key, event.EventID, journal); e != nil {
			audit.Persisted = false
			audit.Issues = append(audit.Issues, "pipeline_audit_write_failed")
		}
	}
	prepared.Evidence.Pipeline = &audit
	var projected map[string]any
	if json.Unmarshal([]byte(prepared.Context), &projected) == nil {
		projected["evidence_pipeline"] = map[string]any{"version": audit.Version, "audit_key": audit.Key, "catalog_size": len(audit.Checks), "states": audit.Counts, "persisted": audit.Persisted}
		if raw, e := json.Marshal(projected); e == nil {
			prepared.Context = string(raw)
		}
	}
	return prepared, nil
}

// Keep all non-phase-one facts. Phase-one replacements alone are computed from
// verified independent contacts, not packet-count time series.
func mergePipelineFacts(all, independent []evidence.Finding) []evidence.Finding {
	ids := map[evidence.FactID]bool{}
	for _, id := range evidence.PhaseOneFacts() {
		ids[id] = true
	}
	ids[evidence.BeaconPeriodic], ids[evidence.MultiDayPersist] = true, true
	out := make([]evidence.Finding, 0, len(all)+len(independent))
	replaced := map[evidence.FactID]bool{}
	for _, f := range independent {
		replaced[f.FactID] = true
	}
	for _, f := range all {
		if !ids[f.FactID] {
			out = append(out, f)
		} else if !replaced[f.FactID] {
			// Absent independently verified observations cannot preserve a
			// preliminary packet-based positive/negative, but still get a row.
			if f.Status != evidence.Missing {
				f.Status, f.Eligibility, f.Quality, f.ReasonCode = evidence.Missing, "ineligible", "partial", evidence.MissingInput
				f.Measurements = evidence.Measurements{}
				f.Limitations = append(f.Limitations, "independently verified observation supply unavailable")
			}
			out = append(out, f)
		}
	}
	return append(out, independent...)
}

func phaseOnePipelineFacts(all []evidence.Finding) []evidence.Finding {
	ids := map[evidence.FactID]bool{}
	for _, id := range evidence.PhaseOneFacts() {
		ids[id] = true
	}
	out := []evidence.Finding{}
	for _, f := range all {
		if ids[f.FactID] {
			out = append(out, f)
		}
	}
	return out
}

// Catalog totals are independent of scope/task instance totals. A mixed rule
// retains every instance state; any missing/error prevents an aggregate negative.
func pipelineAudit(eventID string, facts SnapshotFactEvaluation, sem ReportSemanticEvaluation) EvidencePipelineAudit {
	a := EvidencePipelineAudit{Version: EvidencePipelineVersion, EventID: eventID, SnapshotVersion: facts.Manifest.SnapshotVersion, Watermark: facts.Manifest.Watermark, RevisionWatermark: facts.Manifest.RevisionWatermark, RuleVersion: evidence.RuleVersion, SemanticVersion: evidence.SemanticVersion, NormalizationVersion: evidence.NormalizationVersion, Counts: map[string]int{"observed": 0, "not_observed": 0, "missing": 0, "not_applicable": 0, "execution_error": 0, "skipped": 0}, ExpectedFacts: 59, ExpectedSemantics: 23, Total: 82}
	for _, id := range evidence.SupportedFacts() {
		check := PipelineCheck{ID: string(id), Kind: "fact", States: map[string]int{}, Reasons: map[string]int{}}
		if facts.Result != nil {
			for _, f := range facts.Result.Findings {
				if f.FactID == id {
					state := string(f.Status)
					if f.ReasonCode == "rule_execution_error" {
						state = "execution_error"
					}
					check.States[state]++
					check.Reasons[string(f.ReasonCode)]++
					check.Instances++
					if f.Status == evidence.Observed || f.Status == evidence.NotObserved {
						a.ExecutedInstances++
						a.AcceptedInstances++
					}
				}
			}
		}
		if check.Instances == 0 {
			check.States["missing"] = 1
			check.Reason = firstNonEmpty(facts.Reason, "fact_inputs_unavailable")
		}
		check.Status = pipelineRollup(check.States)
		a.Checks = append(a.Checks, check)
		a.Counts[check.Status]++
	}
	for _, definition := range evidence.SemanticDefinitions() {
		check := PipelineCheck{ID: definition.Key.String(), Kind: "semantic", States: map[string]int{}, Reasons: map[string]int{}}
		if sem.Result != nil {
			findings := map[string]evidence.SemanticFinding{}
			for _, f := range sem.Result.Findings {
				findings[f.TaskID] = f
			}
			for _, x := range sem.Result.Plan.Executions {
				if x.Slot != definition.Key {
					continue
				}
				state := "missing"
				switch x.Status {
				case "accepted":
					f, ok := findings[x.TaskID]
					if ok && f.StructureValidation == "passed" {
						state = evidence.SemanticTerminalState(x, &f)
						a.ExecutedInstances++
						a.AcceptedInstances++
						a.SemanticSummary.Accepted++
						switch f.Judgement {
						case "support":
							a.SemanticSummary.Support++
						case "neutral":
							a.SemanticSummary.Neutral++
						case "contradict":
							a.SemanticSummary.Contradict++
						}
						if definition.ExplanationOnly {
							a.SemanticSummary.ExplanationOnly++
						}
						if evidence.SemanticRiskSupportEligible(f) {
							a.SemanticSummary.MaliciousSupportEligible++
						}
					} else {
						state = "execution_error"
					}
				case "rejected", "unavailable":
					state = "execution_error"
					a.ExecutedInstances++
				case "planned":
					state = "skipped"
				case "skipped":
					// Missing prerequisites are missing, not a refutation.
					if x.Reason == "not_requested" {
						state = "skipped"
					}
				}
				check.States[state]++
				check.Reasons[firstNonEmpty(x.Reason, x.Status)]++
				check.Instances++
			}
		}
		if check.Instances == 0 {
			state := "missing"
			if sem.Status == "disabled" {
				state = "skipped"
			}
			check.States[state] = 1
			check.Reason = firstNonEmpty(sem.Reason, "semantic_prerequisites_unavailable")
		}
		check.Status = pipelineRollup(check.States)
		a.Checks = append(a.Checks, check)
		a.Counts[check.Status]++
	}
	a.Completed = len(a.Checks)
	a.CatalogTotal, a.CatalogTerminalCount = a.Total, a.Completed
	return a
}

func pipelineRollup(states map[string]int) string {
	for _, state := range []string{"observed", "execution_error", "missing", "skipped", "neutral", "contradict", "explanation", "not_observed", "not_applicable"} {
		if states[state] > 0 {
			return state
		}
	}
	return "missing"
}

// C is the only additive layer. Keep its actual contributions alongside the
// 82 F/S scheduling records; F and S always retain zero score contribution.
func attachPipelineJointNormalization(b *ReportEvidenceBundle) {
	if b.PhaseOne == nil {
		return
	}
	remaining := b.PhaseOne.Result.Score
	for _, unit := range b.PhaseOne.Result.Units {
		var window *evidence.Window
		coverage := "validated_join"
		if unit.Fact != nil {
			window = unit.Fact.Window
			coverage = unit.Fact.Quality
		}
		contribution := min(unit.Score, max(remaining, 0))
		remaining -= contribution
		identity := unit.IOCType + ":" + unit.IOCValue + ":" + unit.SemanticTask
		if unit.Fact != nil {
			identity += ":" + unit.Fact.ObservationKind
		}
		u := evidence.UnifiedEvidence{ID: evidence.UnifiedID("joint", unit.ID, unit.Scope, window, identity), IOCType: unit.IOCType, IOCValue: unit.IOCValue, Kind: "joint", RuleID: unit.ID, SnapshotVersion: b.SnapshotVersion, Scope: unit.Scope, Window: window, Status: unit.Status, TerminalStatus: unit.Status, Quality: coverage, Coverage: coverage, Role: "joint_evidence", Reason: unit.Reason, SourceIDs: unit.SourceIDs, Version: evidence.PhaseOneVersion, ScoreEligible: unit.Status == "observed" && unit.Score > 0 && unit.DuplicateOf == "", ScoreContribution: contribution, DuplicateOf: unit.DuplicateOf, DedupGroup: "joint:" + unit.Family + ":" + scopeKey(unit.Scope)}
		u.FeatureClaim = "validated phase-one joint predicate " + unit.ID
		u.CannotProve = "Policy evidence points are not calibrated probabilities or proof of attack success."
		if unit.Fact != nil {
			m := unit.Fact.Measurements
			u.Measurements = &m
			u.Dependencies = unit.Fact.Dependencies
		}
		b.Normalized.Items = append(b.Normalized.Items, u)
	}
	b.Normalized.Recount()
	b.Digest.TotalInstances = len(b.Normalized.Items)
	b.Digest.Counts = b.Normalized.Counts
	b.Digest.GapReasons = b.Normalized.Reasons
}
