package evidence

import (
	"fmt"
	"sort"
)

const PhaseOneVersion = "evidence-phase1-v1.0"

type PhaseOneDefinition struct {
	ID       string    `json:"id"`
	Fact     FactID    `json:"fact,omitempty"`
	Slots    []SlotKey `json:"slots,omitempty"`
	NeedsIOC bool      `json:"needs_ioc"`
	Family   string    `json:"family"`
}

func PhaseOneDefinitions() []PhaseOneDefinition {
	return []PhaseOneDefinition{
		{"C01", "F_HIST_ASSET_IOC_RECURRENCE", nil, true, "history"},
		{"C02", "F_BEACON_JITTER", nil, true, "time"},
		{"C03", "F_FIXED_DAILY_WINDOW", nil, true, "time"},
		{"C04", "F_HTTP_ENDPOINT_REPEAT", nil, true, "http_repeat"},
		{"C05", "", []SlotKey{{ID: "S01", Target: "c2.command_intent"}, {ID: "S13", Target: "payload.decoded_intent", Subtype: "command"}}, false, "payload"},
		{"C06", "", []SlotKey{{ID: "S09", Target: "exploit.payload_intent"}}, false, "payload"},
		{"C07", "F_DNS_ENCODED_LABEL", []SlotKey{{ID: "S04", Target: "c2.dns_encoded_intent"}}, false, "payload"},
	}
}
func PhaseOneFacts() []FactID {
	return []FactID{"F_HIST_ASSET_IOC_RECURRENCE", "F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW", "F_HTTP_ENDPOINT_REPEAT", "F_DNS_ENCODED_LABEL"}
}
func PhaseOneSlots() []SlotKey {
	return []SlotKey{{ID: "S01", Target: "c2.command_intent"}, {ID: "S04", Target: "c2.dns_encoded_intent"}, {ID: "S09", Target: "exploit.payload_intent"}, {ID: "S13", Target: "payload.decoded_intent", Subtype: "command"}}
}

// Binding is supplied only by a wire parser. Upstream owns reputation/review/TTL.
type PhaseOneBinding struct {
	Scope    Scope  `json:"scope"`
	IOCType  string `json:"ioc_type"`
	IOCValue string `json:"ioc_value"`
	Field    string `json:"field"`
	SourceID string `json:"source_id"`
	Verified bool   `json:"verified"`
	Reason   string `json:"reason,omitempty"`
}
type PhaseOneConfig struct {
	Version  string         `json:"version"`
	Points   map[string]int `json:"points"`
	MaxScore int            `json:"max_score"`
}

func DefaultPhaseOneConfig() PhaseOneConfig {
	return PhaseOneConfig{Version: "phase1-score-v1", Points: map[string]int{"C01": 10, "C02": 15, "C03": 10, "C04": 15, "C05": 20, "C06": 20, "C07": 20}, MaxScore: 100}
}
func (c PhaseOneConfig) Validate() error {
	if c.Version == "" || c.MaxScore < 1 || c.MaxScore > 1000 || len(c.Points) != 7 {
		return fmt.Errorf("invalid phase-one score config")
	}
	for _, d := range PhaseOneDefinitions() {
		n, ok := c.Points[d.ID]
		if !ok || n < 0 || n > 1000 {
			return fmt.Errorf("invalid points for %s", d.ID)
		}
	}
	return nil
}

type PhaseOneUnit struct {
	IOCType      string            `json:"ioc_type,omitempty"`
	IOCValue     string            `json:"ioc_value,omitempty"`
	ID           string            `json:"id"`
	Scope        Scope             `json:"scope"`
	Status       string            `json:"status"`
	Reason       string            `json:"reason"`
	Fact         *Finding          `json:"fact,omitempty"`
	SemanticTask string            `json:"semantic_task,omitempty"`
	SourceIDs    []string          `json:"source_ids"`
	IOCBindings  []PhaseOneBinding `json:"ioc_bindings,omitempty"`
	Score        int               `json:"score"`
	DuplicateOf  string            `json:"duplicate_of,omitempty"`
	Family       string            `json:"family"`
}
type PhaseOneResult struct {
	Version         string         `json:"version"`
	EventID         string         `json:"event_id"`
	SnapshotVersion int64          `json:"snapshot_version"`
	Policy          PhaseOneConfig `json:"policy"`
	Score           int            `json:"score"`
	ScoreMeaning    string         `json:"score_meaning"`
	Units           []PhaseOneUnit `json:"units"`
	Diagnostics     []string       `json:"diagnostics"`
}

// EvaluatePhaseOne joins validated F/S evidence. Scores are policy points, never
// calibrated probabilities. No model-provided numeric value enters this path.
func EvaluatePhaseOne(event string, version int64, facts []Finding, sem *SemanticResult, bindings []PhaseOneBinding, cfg PhaseOneConfig) (PhaseOneResult, error) {
	out := PhaseOneResult{Version: PhaseOneVersion, EventID: event, SnapshotVersion: version, Policy: cfg, ScoreMeaning: "policy_evidence_points_not_probability", Units: []PhaseOneUnit{}, Diagnostics: []string{}}
	if err := cfg.Validate(); err != nil {
		return out, err
	}
	scopes := map[Scope]bool{}
	for _, b := range bindings {
		scopes[b.Scope] = true
	}
	for _, f := range facts {
		scopes[f.Scope] = true
	}
	sem = phaseOneValidatedSemantics(event, version, sem)
	validSem := sem != nil
	if sem != nil && !validSem {
		out.Diagnostics = append(out.Diagnostics, "semantic_result_binding_invalid")
	}
	if validSem {
		for _, f := range sem.Findings {
			scopes[f.Scope] = true
		}
	}
	if len(scopes) == 0 {
		scopes[Scope{}] = true
	}
	ordered := []Scope{}
	for s := range scopes {
		if s.GroupID == "" {
			ordered = append(ordered, s)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return fmt.Sprint(ordered[i]) < fmt.Sprint(ordered[j]) })
	for _, scope := range ordered {
		for _, d := range PhaseOneDefinitions() {
			identities := [][2]string{{"", ""}}
			if d.NeedsIOC {
				identities = nil
				seen := map[[2]string]bool{}
				for _, b := range bindings {
					if b.Scope == scope && b.Verified {
						k := [2]string{b.IOCType, b.IOCValue}
						if !seen[k] {
							seen[k] = true
							identities = append(identities, k)
						}
					}
				}
				if len(identities) == 0 {
					identities = append(identities, [2]string{})
				}
				sort.Slice(identities, func(i, j int) bool { return fmt.Sprint(identities[i]) < fmt.Sprint(identities[j]) })
			}
			for _, identity := range identities {
				u := PhaseOneUnit{ID: d.ID, Scope: scope, Status: "missing", Reason: "required_material_unavailable", Family: d.Family, SourceIDs: []string{}}
				u.IOCType, u.IOCValue = identity[0], identity[1]
				for _, b := range bindings {
					if b.Scope == scope && b.Verified && b.IOCType != "" && b.IOCValue != "" && b.Field != "" && b.SourceID != "" && (!d.NeedsIOC || b.IOCType == u.IOCType && b.IOCValue == u.IOCValue) {
						u.IOCBindings = append(u.IOCBindings, b)
					}
				}
				if d.NeedsIOC && len(u.IOCBindings) == 0 {
					u.Reason = "ioc_wire_binding_missing"
					out.Units = append(out.Units, u)
					continue
				}
				factOK := d.Fact == ""
				for _, f := range facts {
					if f.FactID == d.Fact && f.Scope == scope && f.SnapshotVersion == version && (!d.NeedsIOC || f.IOCType == u.IOCType && f.IOCValue == u.IOCValue) {
						if d.ID == "C07" && f.Status != Observed {
							continue
						}
						copy := f
						u.Fact = &copy
						u.SourceIDs = append(u.SourceIDs, f.SourceIDs...)
						factOK = f.Status == Observed && f.Eligibility == "eligible"
						u.Reason = string(f.ReasonCode)
						if f.Status == NotObserved {
							u.Status = "not_observed"
						}
						break
					}
				}
				if !factOK {
					out.Units = append(out.Units, u)
					continue
				}
				semanticOK := len(d.Slots) == 0
				if validSem {
					for _, f := range sem.Findings {
						if f.Scope != scope || f.Judgement != "support" || f.Strength == "none" || f.ExplanationOnly || f.DuplicateOf != "" {
							continue
						}
						for _, slot := range d.Slots {
							if f.Slot == slot {
								// Same DNS operation must supply the hard fact and decoded semantics.
								taskSources := []string{}
								for _, task := range sem.Plan.Tasks {
									if task.ID == f.TaskID {
										for _, m := range task.Materials {
											taskSources = append(taskSources, m.SourceIDs...)
										}
									}
								}
								if d.ID == "C07" {
									matched := false
									for _, hard := range facts {
										if hard.FactID == d.Fact && hard.Scope == scope && hard.Status == Observed && hard.Eligibility == "eligible" && phaseOneOverlap(hard.SourceIDs, taskSources) {
											copy := hard
											u.Fact = &copy
											u.SourceIDs = append([]string(nil), hard.SourceIDs...)
											matched = true
											break
										}
									}
									if !matched {
										continue
									}
								}
								semanticOK = true
								u.SemanticTask = f.TaskID
								u.SourceIDs = append(u.SourceIDs, taskSources...)
								break
							}
						}
						if semanticOK {
							break
						}
					}
				}
				if semanticOK {
					u.Status = "observed"
					u.Reason = "joint_conditions_met"
					u.Score = cfg.Points[d.ID]
				} else {
					u.Status = "missing"
					u.Reason = "accepted_phase_one_semantics_missing"
				}
				u.SourceIDs = unique(u.SourceIDs)
				sort.Strings(u.SourceIDs)
				out.Units = append(out.Units, u)
			}
		}
	}
	// Resolve same time-family and same raw payload deterministically by points,
	// then unit/scope identity. The losing unit remains visible with zero points.
	indexes := []int{}
	for i, u := range out.Units {
		if u.Status == "observed" {
			indexes = append(indexes, i)
		}
	}
	sort.SliceStable(indexes, func(i, j int) bool {
		a, b := out.Units[indexes[i]], out.Units[indexes[j]]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.ID+fmt.Sprint(a.Scope) < b.ID+fmt.Sprint(b.Scope)
	})
	accepted := []int{}
	for _, i := range indexes {
		u := &out.Units[i]
		for _, j := range accepted {
			a := out.Units[j]
			if a.Family == "history" && u.Family == "history" && a.Scope.AssetID == u.Scope.AssetID && a.Scope.DeviceID == u.Scope.DeviceID && a.IOCType == u.IOCType && a.IOCValue == u.IOCValue && phaseOneOverlap(a.SourceIDs, u.SourceIDs) {
				u.Score = 0
				u.DuplicateOf = a.ID + ":" + fmt.Sprint(a.Scope)
				u.Reason = "same_source_non_additive"
				break
			}
			if a.Scope != u.Scope {
				continue
			}
			if a.Family == u.Family && (u.Family == "time" && a.IOCType == u.IOCType && a.IOCValue == u.IOCValue || u.Family == "payload" && phaseOneOverlap(a.SourceIDs, u.SourceIDs)) {
				u.Score = 0
				u.DuplicateOf = a.ID + ":" + fmt.Sprint(a.Scope)
				u.Reason = "same_source_non_additive"
				break
			}
		}
		if u.DuplicateOf == "" {
			accepted = append(accepted, i)
			out.Score += u.Score
		}
	}
	if out.Score > cfg.MaxScore {
		out.Score = cfg.MaxScore
	}
	return out, nil
}

// A rejected task cannot erase a different accepted task. Validate each accepted
// operation, including quotes and transaction bindings, against its own plan.
func phaseOneValidatedSemantics(event string, version int64, sem *SemanticResult) *SemanticResult {
	if sem == nil || sem.Plan.EventID != event || sem.Plan.SnapshotVersion != version {
		return nil
	}
	out := *sem
	out.Findings = nil
	for _, finding := range sem.Findings {
		for _, task := range sem.Plan.Tasks {
			if task.ID != finding.TaskID {
				continue
			}
			accepted := false
			for _, x := range sem.Plan.Executions {
				if x.TaskID == task.ID && x.Status == "accepted" && x.Reason == "references_and_strength_validated" {
					accepted = true
				}
			}
			if !accepted {
				continue
			}
			one := *sem
			one.Plan.Tasks = []SemanticTask{task}
			one.Plan.Executions = nil
			one.Findings = []SemanticFinding{finding}
			if ValidateSemanticResult(one.Plan, one) == nil {
				out.Findings = append(out.Findings, finding)
			}
		}
	}
	return &out
}
func phaseOneOverlap(a, b []string) bool {
	m := map[string]bool{}
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if m[s] {
			return true
		}
	}
	return false
}
