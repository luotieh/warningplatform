package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

const NormalizationVersion = "evidence-normalization-0.2"

// UnifiedEvidence is an audit record, not a score. A measured observation,
// an interpretation, a negative result and a skipped check remain distinct.
type UnifiedEvidence struct {
	EvidenceContract
	StructureValidation string        `json:"structure_validation,omitempty"`
	BehaviorOutcome     string        `json:"behavior_outcome,omitempty"`
	ID                  string        `json:"id"`
	ReportID            string        `json:"report_id,omitempty"`
	Kind                string        `json:"kind"`
	RuleID              string        `json:"rule_id"`
	TaskID              string        `json:"task_id,omitempty"`
	SubjectID           string        `json:"subject_id,omitempty"`
	SnapshotVersion     int64         `json:"snapshot_version,omitempty"`
	ExecutionStatus     string        `json:"execution_status,omitempty"`
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

// Normalize covers every actual instance and registers unavailable catalog
// entries when a whole rule/slot has no result. No database or model call occurs.
func Normalize(facts []Finding, sem *SemanticResult, executions ...[]Execution) NormalizedEvidence {
	n := NormalizedEvidence{Version: NormalizationVersion, Items: []UnifiedEvidence{}}
	seenFacts, seenSlots := map[FactID]bool{}, map[SlotKey]bool{}
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
				if x.FactID == f.FactID && x.Scope == f.Scope {
					execution = x.Status
					break
				}
			}
		}
		n.Items = append(n.Items, UnifiedEvidence{ID: UnifiedID("fact", string(f.FactID), f.Scope, f.Window, ""), Kind: "fact", RuleID: string(f.FactID), Scope: f.Scope, Window: f.Window, Status: string(f.Status), Quality: f.Quality, Role: role, Reason: string(f.ReasonCode), Measurements: &m, Parameters: &params, SourceIDs: f.SourceIDs, Dependencies: f.Dependencies, Limitations: f.Limitations, Version: f.RuleVersion, SnapshotVersion: f.SnapshotVersion, ExecutionStatus: execution})
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
			}
			u.SourceIDs = unique(u.SourceIDs)
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
	for _, d := range SemanticDefinitions() {
		if !seenSlots[d.Key] {
			n.Items = append(n.Items, UnifiedEvidence{ID: UnifiedID("semantic", d.Key.String(), Scope{}, nil, ""), Kind: "semantic", RuleID: d.Key.String(), Status: "unavailable", Quality: "unknown", Role: "gap", Reason: "no_execution_result", Version: SemanticVersion})
		}
	}
	for i := range n.Items {
		if n.Items[i].Kind == "fact" {
			n.Items[i].EvidenceContract = contractForFact(FactID(n.Items[i].RuleID))
		} else {
			for _, d := range SemanticDefinitions() {
				if d.Key.String() == n.Items[i].RuleID {
					n.Items[i].EvidenceContract = d.EvidenceContract
				}
			}
		}
	}
	sort.SliceStable(n.Items, func(i, j int) bool { return n.Items[i].ID < n.Items[j].ID })
	n.Recount()
	return n
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
