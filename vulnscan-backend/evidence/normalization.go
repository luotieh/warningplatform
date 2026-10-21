package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

const NormalizationVersion = "evidence-normalization-0.4"

// UnifiedEvidence is an audit record, not a score. A measured observation,
// an interpretation, a negative result and a skipped check remain distinct.
type UnifiedEvidence struct {
	IOCType         string `json:"ioc_type,omitempty"`
	IOCValue        string `json:"ioc_value,omitempty"`
	ObservationKind string `json:"observation_kind,omitempty"`
	EvidenceContract
	TerminalStatus      string        `json:"terminal_status"`
	Coverage            string        `json:"coverage,omitempty"`
	ModelVersion        string        `json:"model_version,omitempty"`
	InputDigest         string        `json:"input_digest,omitempty"`
	DedupGroup          string        `json:"dedup_group,omitempty"`
	ScoreEligible       bool          `json:"score_eligible"`
	ScoreContribution   int           `json:"score_contribution"`
	StructureValidation string        `json:"structure_validation,omitempty"`
	SemanticRole        string        `json:"semantic_role,omitempty"`
	RiskSupportEligible bool          `json:"risk_support_eligible"`
	BehaviorOutcome     string        `json:"behavior_outcome,omitempty"`
	ID                  string        `json:"id"`
	ReportID            string        `json:"report_id,omitempty"`
	Kind                string        `json:"kind"`
	RuleID              string        `json:"rule_id"`
	TaskID              string        `json:"task_id,omitempty"`
	SubjectID           string        `json:"subject_id,omitempty"`
	SnapshotVersion     int64         `json:"snapshot_version,omitempty"`
	ExecutionStatus     string        `json:"execution_status,omitempty"`
	TaskExecutionStatus string        `json:"task_execution_status,omitempty"`
	ModelJudgement      string        `json:"model_judgement,omitempty"`
	Scope               Scope         `json:"scope"`
	Window              *Window       `json:"window,omitempty"`
	Status              string        `json:"status"`
	Quality             string        `json:"quality"`
	Role                string        `json:"role"`
	Reason              string        `json:"reason,omitempty"`
	Judgement           string        `json:"judgement,omitempty"`
	Strength            string        `json:"strength,omitempty"`
	Measurements        *Measurements `json:"measurements,omitempty"`
	Parameters          *Parameters   `json:"parameters,omitempty"`
	Interpretation      string        `json:"interpretation,omitempty"`
	SourceIDs           []string      `json:"source_ids,omitempty"`
	Dependencies        []Dependency  `json:"dependencies,omitempty"`
	NonAdditiveWith     []string      `json:"non_additive_with,omitempty"`
	DuplicateOf         string        `json:"duplicate_of,omitempty"`
	Limitations         []string      `json:"limitations,omitempty"`
	Version             string        `json:"version"`
}

type NormalizedEvidence struct {
	Version string            `json:"version"`
	Items   []UnifiedEvidence `json:"items"`
	Counts  map[string]int    `json:"counts"`
	Reasons map[string]int    `json:"reasons"`
}

func UnifiedID(kind, rule string, scope Scope, window *Window, task string) string {
	raw, _ := json.Marshal([]any{kind, rule, scope, window, task})
	h := sha256.Sum256(raw)
	return "N" + hex.EncodeToString(h[:8])
}

func FindingUnifiedID(f Finding) string {
	identity := ""
	if f.IOCType != "" || f.IOCValue != "" || f.ObservationKind != "" {
		raw, _ := json.Marshal([]string{f.IOCType, f.IOCValue, f.ObservationKind})
		identity = string(raw)
	}
	return UnifiedID("fact", string(f.FactID), f.Scope, f.Window, identity)
}

// Normalize covers every actual instance and registers unavailable catalog
// entries when a whole rule/slot has no result. No database or model call occurs.
func Normalize(facts []Finding, sem *SemanticResult, executions ...[]Execution) NormalizedEvidence {
	n := NormalizedEvidence{Version: NormalizationVersion, Items: []UnifiedEvidence{}}
	seenFacts, seenSlots := map[FactID]bool{}, map[SlotKey]bool{}
	semanticDefinitions := SemanticDefinitions()
	semanticContracts := map[string]EvidenceContract{}
	for _, d := range semanticDefinitions {
		semanticContracts[d.Key.String()] = d.EvidenceContract
	}
	for _, f := range facts {
		seenFacts[f.FactID] = true
		role := "gap"
		if f.Status == Observed {
			role = "measured_fact"
		}
		if f.Status == NotObserved {
			role = "negative_result"
		}
		m := f.Measurements
		params := f.Parameters
		execution := ""
		if len(executions) > 0 {
			for _, x := range executions[0] {
				if x.FactID == f.FactID && x.Scope == f.Scope && x.IOCType == f.IOCType && x.IOCValue == f.IOCValue && x.ObservationKind == f.ObservationKind {
					execution = x.Status
					break
				}
			}
		}
		n.Items = append(n.Items, UnifiedEvidence{ID: FindingUnifiedID(f), IOCType: f.IOCType, IOCValue: f.IOCValue, ObservationKind: f.ObservationKind, Kind: "fact", RuleID: string(f.FactID), Scope: f.Scope, Window: f.Window, Status: string(f.Status), Quality: f.Quality, Role: role, Reason: string(f.ReasonCode), Measurements: &m, Parameters: &params, SourceIDs: f.SourceIDs, Dependencies: f.Dependencies, Limitations: f.Limitations, Version: f.RuleVersion, SnapshotVersion: f.SnapshotVersion, ExecutionStatus: execution})
	}
	if sem != nil {
		findings, tasks := map[string]SemanticFinding{}, map[string]SemanticTask{}
		for _, f := range sem.Findings {
			findings[f.TaskID] = f
		}
		for _, t := range sem.Plan.Tasks {
			tasks[t.ID] = t
		}
		for _, x := range sem.Plan.Executions {
			seenSlots[x.Slot] = true
			u := UnifiedEvidence{Kind: "semantic", RuleID: x.Slot.String(), TaskID: x.TaskID, SubjectID: x.SubjectID, Status: x.Status, ExecutionStatus: x.Status, Reason: x.Reason, Quality: "unknown", Role: "gap", Version: sem.Plan.RuleVersion, SnapshotVersion: sem.Plan.SnapshotVersion}
			if t, ok := tasks[x.TaskID]; ok {
				u.Scope = t.Scope
				u.Window = &Window{Start: t.Window.Start, End: t.Window.End, Convention: "analysis_half_open"}
				for _, m := range t.Materials {
					u.SourceIDs = append(u.SourceIDs, m.SourceIDs...)
					u.Dependencies = append(u.Dependencies, Dependency{Kind: m.Kind, Version: m.SourceVersion, SourceIDs: m.SourceIDs})
				}
			}
			if f, ok := findings[x.TaskID]; ok {
				u.StructureValidation, u.BehaviorOutcome = "passed", "not_established"
				u.Role, u.Quality, u.Judgement, u.Strength = "interpretation", "structure_validated", f.Judgement, f.Strength
				u.Interpretation, u.NonAdditiveWith, u.DuplicateOf, u.Limitations = f.Explanation, f.NonAdditiveWith, f.DuplicateOf, f.Limitations
				if f.ExplanationOnly {
					u.Role = "context_interpretation"
				}
				if f.DuplicateOf != "" {
					u.Role = "duplicate"
				}
				u.SemanticRole = "risk_support"
				if f.ExplanationOnly {
					u.SemanticRole = "background_explanation"
				}
				if x.Slot.ID == "S14" || x.Slot.ID == "SC02" || x.Slot.ID == "R07" {
					u.SemanticRole = "alternative_explanation"
				}
				if x.Slot.ID == "S15" {
					u.SemanticRole = "information_gaps"
				}
				u.RiskSupportEligible = SemanticRiskSupportEligible(f)
			}
			u.SourceIDs = unique(u.SourceIDs)
			u.TaskExecutionStatus, u.ModelJudgement = u.ExecutionStatus, u.Judgement
			// Subject disambiguates skipped executions that have no task ID.
			u.ID = UnifiedID(u.Kind, u.RuleID, u.Scope, u.Window, x.SubjectID+":"+x.TaskID)
			n.Items = append(n.Items, u)
		}
	}
	for _, d := range Definitions() {
		if !seenFacts[d.ID] {
			n.Items = append(n.Items, UnifiedEvidence{ID: UnifiedID("fact", string(d.ID), Scope{}, nil, ""), Kind: "fact", RuleID: string(d.ID), Status: "unavailable", Quality: "unknown", Role: "gap", Reason: "no_execution_result", Version: RuleVersion})
		}
	}
	for _, d := range semanticDefinitions {
		if !seenSlots[d.Key] {
			n.Items = append(n.Items, UnifiedEvidence{ID: UnifiedID("semantic", d.Key.String(), Scope{}, nil, ""), Kind: "semantic", RuleID: d.Key.String(), Status: "unavailable", Quality: "unknown", Role: "gap", Reason: "no_execution_result", Version: SemanticVersion})
		}
	}
	for i := range n.Items {
		n.Items[i].TerminalStatus = normalizedTerminalState(n.Items[i], sem != nil && sem.CoverageIncomplete)
		if n.Items[i].Kind == "fact" {
			n.Items[i].EvidenceContract = contractForFact(FactID(n.Items[i].RuleID))
		} else {
			n.Items[i].EvidenceContract = semanticContracts[n.Items[i].RuleID]
		}
	}
	sort.SliceStable(n.Items, func(i, j int) bool { return n.Items[i].ID < n.Items[j].ID })
	n.Recount()
	return n
}

func normalizedTerminalState(u UnifiedEvidence, incomplete bool) string {
	if u.Reason == "rule_execution_error" {
		return "execution_error"
	}
	if u.Kind == "fact" {
		if u.Status == "observed" || u.Status == "not_observed" || u.Status == "not_applicable" {
			return u.Status
		}
		return "missing"
	}
	switch u.ExecutionStatus {
	case "not_applicable":
		return "not_applicable"
	case "accepted":
		if u.StructureValidation != "passed" {
			return "execution_error"
		}
		if u.Judgement == "support" && u.SemanticRole != "" && u.SemanticRole != "risk_support" {
			return "explanation"
		}
		if u.Judgement == "support" {
			return "observed"
		}
		if u.Judgement == "contradict" {
			return "contradict"
		}
		return "neutral" // accepted and executed; neither absence nor refutation
	case "unavailable", "rejected":
		return "execution_error"
	case "planned":
		return "skipped"
	case "skipped":
		if u.Reason == "not_requested" {
			return "skipped"
		}
	}
	return "missing"
}

// This is eligibility for interpretation as risk support, not a score or
// proof of attack success. C keeps its own stricter, unchanged gates.
func SemanticRiskSupportEligible(f SemanticFinding) bool {
	if f.StructureValidation != "passed" || f.Judgement != "support" || f.Strength == "none" || f.DuplicateOf != "" || f.ExplanationOnly {
		return false
	}
	for _, d := range SemanticDefinitions() {
		if d.Key == f.Slot {
			return !d.ExplanationOnly
		}
	}
	return false
}

func SemanticTerminalState(x SemanticExecution, f *SemanticFinding) string {
	if x.Status == "accepted" {
		if f == nil || f.StructureValidation != "passed" {
			return "execution_error"
		}
		if f.Judgement == "neutral" {
			return "neutral"
		}
		if f.Judgement == "contradict" {
			return "contradict"
		}
		for _, d := range SemanticDefinitions() {
			if d.Key == f.Slot && d.ExplanationOnly {
				return "explanation"
			}
		}
		return "observed"
	}
	switch x.Status {
	case "not_applicable":
		return "not_applicable"
	case "rejected", "unavailable":
		return "execution_error"
	case "planned":
		return "skipped"
	case "skipped":
		if x.Reason == "not_requested" {
			return "skipped"
		}
	}
	return "missing"
}

func (n *NormalizedEvidence) Recount() {
	n.Counts, n.Reasons = map[string]int{}, map[string]int{}
	for _, u := range n.Items {
		n.Counts[u.Kind+":"+u.Status]++
		if u.Role == "gap" {
			n.Reasons[u.Reason]++
		}
	}
}
