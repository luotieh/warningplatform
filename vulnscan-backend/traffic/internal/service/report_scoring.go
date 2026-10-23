package service

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"vulnscan-backend/evidence"
)

const reportJudgementVersion = "0.2"
const reportScoringVersion = "report-score-v0.2"

type ReportScoreItem struct {
	ID          string                `json:"id"`
	Key         string                `json:"implementation_key"`
	Scope       evidence.Scope        `json:"scope"`
	Window      *evidence.Window      `json:"window,omitempty"`
	Sources     []string              `json:"source_refs,omitempty"`
	Relations   []evidence.Dependency `json:"relations,omitempty"`
	Strength    float64               `json:"strength"`
	Reliability float64               `json:"reliability"`
	Binding     float64               `json:"binding"`
	X           float64               `json:"effective_strength"`
	Reason      string                `json:"factor_reason"`
}
type ReportScoreContribution struct {
	Rule        string   `json:"rule"`
	EvidenceIDs []string `json:"evidence_ids"`
	Value       float64  `json:"value"`
	Reason      string   `json:"reason"`
}
type ReportThreatScore struct {
	Type          string                    `json:"type"`
	Base          float64                   `json:"base"`
	Raw           float64                   `json:"raw"`
	Z             float64                   `json:"z"`
	Cap           float64                   `json:"cap"`
	HasBehavior   bool                      `json:"has_type_behavior"`
	HasDirect     bool                      `json:"has_direct_evidence"`
	Contributions []ReportScoreContribution `json:"contributions"`
	Combinations  []ReportScoreContribution `json:"combinations"`
	Counters      []ReportScoreContribution `json:"counters"`
}
type ReportModelAdjustment struct {
	Delta       int      `json:"delta"`
	Reason      string   `json:"reason"`
	EvidenceIDs []string `json:"evidence_ids"`
	ContextKey  string   `json:"uncovered_context_key"`
	Invalid     string   `json:"-"`
}

func (a *ReportModelAdjustment) UnmarshalJSON(raw []byte) error {
	type plain ReportModelAdjustment
	var value plain
	err := json.Unmarshal(raw, &value)
	*a = ReportModelAdjustment(value)
	if err != nil {
		a.Invalid = "invalid_adjustment_fields"
	}
	// A malformed optional adjustment is rejected independently of report prose.
	return nil
}

type ReportScoreAdjustment struct {
	Proposed      *ReportModelAdjustment `json:"proposed,omitempty"`
	AcceptedDelta int                    `json:"accepted_delta"`
	Reason        string                 `json:"reason"`
}
type ReportScoring struct {
	Version          string                `json:"version"`
	KnowledgeVersion string                `json:"knowledge_version"`
	Formula          string                `json:"formula"`
	Items            []ReportScoreItem     `json:"items"`
	Candidates       []ReportThreatScore   `json:"candidates"`
	SelectedType     string                `json:"selected_type"`
	HasEvidence      bool                  `json:"has_evidence"`
	Adjustment       ReportScoreAdjustment `json:"adjustment"`
	Final            int                   `json:"final"`
}
type reportScoreRow struct {
	keys             []string
	weight, cap      float64
	behavior, direct bool
	limit            string
}
type reportScoreCombo struct {
	id          string
	left, right []string
	weight      float64
	independent bool
}
type reportScoreProfile struct {
	kind   string
	rows   []reportScoreRow
	combos []reportScoreCombo
}

func reportImplementationKey(e ReportEvidence) string {
	if e.Semantic != nil {
		s := e.Semantic.Slot
		return "S:" + s.ID + "/" + s.Target + "/" + s.Subtype
	}
	if e.FactID != "" {
		return string(e.FactID)
	}
	if e.Kind == "intelligence" {
		return "I:" + e.Feature
	}
	return "O:" + e.Feature
}
func reportScoreSources(e ReportEvidence, entries map[string]ReportEvidence) []string {
	refs := append([]string{}, e.SourceIDs...)
	if e.Finding != nil {
		refs = append(refs, e.Finding.SourceIDs...)
	}
	if e.Semantic != nil {
		for _, ref := range e.Semantic.MaterialRefs {
			refs = append(refs, e.MaterialSourceIDs[ref]...)
		}
		for _, id := range e.Semantic.FactRefs {
			for _, f := range entries {
				if f.ID == id || string(f.FactID) == id || (f.Unified != nil && f.Unified.ID == id) {
					refs = append(refs, f.SourceIDs...)
					if f.Finding != nil {
						refs = append(refs, f.Finding.SourceIDs...)
					}
				}
			}
		}
	}
	return reportSortedUnique(refs)
}
func reportSortedUnique(v []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range v {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Factor choices are backend-owned. Missing context never turns into counterevidence.
func reportScoreInput(e ReportEvidence, entries map[string]ReportEvidence) ReportScoreItem {
	i := ReportScoreItem{ID: e.ID, Key: reportImplementationKey(e), Scope: e.Scope, Window: e.Window, Sources: reportScoreSources(e, entries), Reason: "not_eligible_or_unmapped", Binding: 1}
	for _, d := range e.Dependencies {
		if d.Kind == "transfer_join" || d.Kind == "pair" || d.Kind == "redirect_chain" {
			i.Relations = append(i.Relations, d)
		}
	}
	if e.Semantic != nil {
		s := e.Semantic
		if s.ExplanationOnly || s.DuplicateOf != "" || s.Judgement != "support" {
			return i
		}
		i.Strength = map[string]float64{"strong": 1, "medium": .6, "weak": .25}[s.Strength]
		// These findings are accepted by the semantic execution layer, not free report prose.
		if len(s.MaterialRefs) > 0 && len(s.Quotes) > 0 {
			i.Reliability = 1
			i.Reason = "accepted_semantic_with_material_quotes"
		}
	} else if e.Finding != nil {
		f := e.Finding
		if f.Status != evidence.Observed || f.Eligibility != "eligible" {
			return i
		}
		i.Strength = 1
		if len(i.Sources) > 0 {
			if f.Quality == "complete" {
				i.Reliability = 1
				i.Reason = "verified_fact_complete"
			} else if f.Quality == "partial" {
				i.Reliability = .7
				i.Reason = "verified_partial_positive"
			}
		}
	} else if e.Kind == "intelligence" && e.Feature == "ioc_background" && e.Result != "" && e.Source != "" {
		i.Strength = 1
		i.Reliability = .7
		i.Reason = "saved_sourced_intelligence"
	} else if e.Status == "observed" && len(i.Sources) > 0 && len(e.Measurements) > 0 {
		i.Strength = 1
		i.Reliability = 1
		i.Reason = "saved_bound_observation"
	}
	if e.Kind != "intelligence" && (e.Scope.AssetID == "" && e.Scope.GroupID == "" || e.Scope.EndpointID == "") {
		i.Binding = 0
		i.Reason = "unbound_subject_or_endpoint"
	}
	// No inference that every IP is shared. Only explicit observations authorize the reduction.
	if shared, ok := e.Measurements["shared_ip"].(bool); ok && shared {
		if exact, _ := e.Measurements["exact_object_match"].(bool); !exact {
			i.Binding = .4
			i.Reason = "verified_shared_ip_without_exact_object"
		}
	}
	if e.Feature == "schedule" {
		outside, _ := reportScoreNumber(e.Measurements["outside_hits"])
		if outside <= 0 {
			i.Strength = 0
			i.Reason = "no_outside_schedule_observation"
		}
		if strings.Contains(fmt.Sprint(e.Measurements["policy_source"]), "默认") {
			i.Strength = math.Min(i.Strength, .5)
			i.Reason = "default_schedule_weak_context"
		}
	}
	i.X = i.Strength * i.Reliability * i.Binding
	return i
}
func reportScoreNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, e := n.Float64()
		return f, e == nil
	}
	return 0, false
}
func reportScoreMatch(key string, keys []string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}
func reportScoreRelated(a, b ReportScoreItem) bool {
	if a.ID == b.ID || a.Binding == 0 || b.Binding == 0 {
		return false
	}
	if a.Scope.EndpointID == "" || a.Scope.EndpointID != b.Scope.EndpointID {
		return false
	}
	if a.Scope.DeviceID != b.Scope.DeviceID {
		return false
	}
	if a.Scope.GroupID != "" || b.Scope.GroupID != "" {
		if a.Scope.GroupID == "" || a.Scope.GroupID != b.Scope.GroupID {
			return false
		}
	} else if a.Scope.AssetID == "" || a.Scope.AssetID != b.Scope.AssetID {
		return false
	}
	// A relation cannot be manufactured merely from two nearby timestamps.
	if a.Window == nil || b.Window == nil {
		return false
	}
	if !a.Window.End.Before(b.Window.Start) && !b.Window.End.Before(a.Window.Start) {
		return true
	}
	// Verified same-object history rules establish cross-day linkage; ordinary
	// timestamps alone cannot do so for unrelated evidence.
	if strings.HasPrefix(a.Key, "F_HIST_") || strings.HasPrefix(b.Key, "F_HIST_") || a.Key == "F_MULTI_DAY_PERSIST" || b.Key == "F_MULTI_DAY_PERSIST" {
		start, end := a.Window.Start, b.Window.End
		if b.Window.Start.Before(start) {
			start = b.Window.Start
		}
		if a.Window.End.After(end) {
			end = a.Window.End
		}
		return end.Sub(start).Hours() <= 31*24
	}
	return false
}
func reportScoreIndependent(a, b ReportScoreItem) bool {
	if len(a.Sources) == 0 || len(b.Sources) == 0 {
		return false
	}
	for _, x := range a.Sources {
		for _, y := range b.Sources {
			if x == y {
				return false
			}
		}
	}
	return true
}
func reportScoreDuplicate(a, b ReportScoreItem) bool {
	if a.Scope != b.Scope {
		return false
	}
	if len(a.Sources) == 0 || len(b.Sources) == 0 {
		return a.Key == b.Key
	}
	for _, x := range a.Sources {
		for _, y := range b.Sources {
			if x == y {
				return true
			}
		}
	}
	return false
}

func scoreReportThreats(b ReportEvidenceBundle) *ReportScoring {
	out := &ReportScoring{Version: reportScoringVersion, KnowledgeVersion: "KD-v0.2", Formula: "z=-2.2+sum(contributions)+sum(combinations)-sum(counters); P=100/(1+exp(-z)); bounded model delta +/-5", Items: []ReportScoreItem{}, Candidates: []ReportThreatScore{}}
	entries := map[string]ReportEvidence{}
	for _, e := range b.Entries {
		entries[e.ID] = e
	}
	// The scorer and model consume exactly the same bounded evidence projection.
	for _, item := range reportEssenceFor(b).Items {
		if e, ok := entries[item.ID]; ok {
			out.Items = append(out.Items, reportScoreInput(e, entries))
		}
	}
	sort.Slice(out.Items, func(i, j int) bool { return out.Items[i].ID < out.Items[j].ID })
	for _, profile := range reportScoreProfiles() {
		out.Candidates = append(out.Candidates, reportScoreScopedCandidate(profile, out.Items))
	}
	selected := -1
	for j, c := range out.Candidates {
		if c.HasBehavior && (selected < 0 || c.Base > out.Candidates[selected].Base) {
			selected = j
		}
	}
	if selected < 0 {
		for j, c := range out.Candidates {
			if c.Type == "suspicious_contact" {
				selected = j
				break
			}
		}
	}
	if selected >= 0 {
		c := out.Candidates[selected]
		out.SelectedType = c.Type
		out.HasEvidence = len(c.Contributions) > 0
		// Verified contact supports a contact-only report, without adding any
		// malicious points. Do not fail an otherwise valid low-risk report.
		if !out.HasEvidence && c.Type == "suspicious_contact" {
			for _, i := range out.Items {
				if i.Key == "O:saved_activity" && i.X > 0 {
					out.HasEvidence = true
				}
			}
		}
		out.Final = int(math.Round(c.Base))
	}
	return out
}
func reportScoreCandidate(p reportScoreProfile, items []ReportScoreItem) ReportThreatScore {
	c := ReportThreatScore{Type: p.kind, Cap: 59, Z: -2.2, Contributions: []ReportScoreContribution{}, Combinations: []ReportScoreContribution{}, Counters: []ReportScoreContribution{}}
	// Resolve aliases across different rows too (e.g. encoded bytes and their
	// decoded command interpretation), not merely within a row.
	type rankedItem struct {
		item  ReportScoreItem
		value float64
	}
	ranked := []rankedItem{}
	for _, item := range items {
		best := 0.0
		for _, row := range p.rows {
			if reportScoreMatch(item.Key, row.keys) {
				best = math.Max(best, row.weight*item.X)
			}
		}
		if best > 0 {
			ranked = append(ranked, rankedItem{item, best})
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].value != ranked[j].value {
			return ranked[i].value > ranked[j].value
		}
		return ranked[i].item.ID < ranked[j].item.ID
	})
	allowed := map[string]bool{}
	unique := []ReportScoreItem{}
	for _, r := range ranked {
		dup := false
		for _, prev := range unique {
			if reportScoreDuplicate(r.item, prev) && reportScoreSameMeaning(r.item.Key, prev.Key) {
				dup = true
				break
			}
		}
		if !dup {
			allowed[r.item.ID] = true
			unique = append(unique, r.item)
		}
	}
	limits := map[string]float64{}
	direct := []ReportScoreItem{}
	behaviors := []ReportScoreItem{}
	for rowIndex, row := range p.rows {
		matched := []ReportScoreItem{}
		for _, i := range items {
			if allowed[i.ID] && i.X > 0 && reportScoreMatch(i.Key, row.keys) {
				matched = append(matched, i)
			}
		}
		sort.Slice(matched, func(a, b int) bool {
			if matched[a].X != matched[b].X {
				return matched[a].X > matched[b].X
			}
			return matched[a].ID < matched[b].ID
		})
		retained := []ReportScoreItem{}
		sum := 0.0
		for _, i := range matched {
			dup := false
			for _, prev := range retained {
				if reportScoreDuplicate(i, prev) {
					dup = true
					break
				}
			}
			if dup {
				continue
			}
			mult := 1.0
			if len(retained) > 0 {
				mult = .35
			}
			value := row.weight * i.X * mult
			remaining := row.cap - sum
			if row.limit != "" {
				remaining = math.Min(remaining, row.cap-limits[row.limit])
			}
			value = math.Max(0, math.Min(value, remaining))
			if value == 0 {
				continue
			}
			sum += value
			limits[row.limit] += value
			retained = append(retained, i)
			c.Contributions = append(c.Contributions, ReportScoreContribution{Rule: fmt.Sprintf("%s:row-%d:%s", p.kind, rowIndex+1, i.Key), EvidenceIDs: []string{i.ID}, Value: value, Reason: "deduplicated_weight_times_strength"})
			if row.behavior && reportScoreTypeBehavior(p.kind, i) {
				c.HasBehavior = true
			}
			if !strings.HasPrefix(i.Key, "I:") {
				behaviors = append(behaviors, i)
			}
			if row.direct && i.Strength == 1 {
				c.HasDirect = true
				direct = append(direct, i)
			}
		}
		c.Z += sum
	}
	// Strong phishing intent is the conjunction, never a weak URL or a normal login form.
	if p.kind == "phishing_related" {
		for _, a := range items {
			for _, b := range items {
				if a.X > 0 && b.X > 0 && a.Strength == 1 && b.Strength == 1 && reportScoreMatch(a.Key, []string{"S:S05/phishing.deception/", "S:S12/phishing.deception/brand_semantic_impostor"}) && b.Key == "S:S06/phishing.credential_action/" && reportScoreLinkedContent(a, b) {
					c.HasDirect = true
					direct = append(direct, a, b)
				}
			}
		}
	}
	combos := []ReportScoreContribution{}
	for _, rule := range p.combos {
		best := ReportScoreContribution{Rule: rule.id}
		for _, a := range items {
			for _, b := range items {
				if a.X <= 0 || b.X <= 0 || !reportScoreMatch(a.Key, rule.left) || !reportScoreMatch(b.Key, rule.right) || !reportScoreRelated(a, b) {
					continue
				}
				if rule.independent {
					if !reportScoreIndependent(a, b) {
						continue
					}
					if p.kind == "exfiltration_related" && !reportScoreTransactionLinked(a, b) {
						continue
					}
				} else if !reportScoreLinkedContent(a, b) {
					continue
				}
				value := rule.weight * math.Min(a.X, b.X)
				if value > best.Value {
					best = ReportScoreContribution{Rule: rule.id, EvidenceIDs: reportSortedUnique([]string{a.ID, b.ID}), Value: value, Reason: "verified_relation"}
				}
			}
		}
		if best.Value > 0 {
			combos = append(combos, best)
		}
	}
	sort.Slice(combos, func(a, b int) bool {
		if combos[a].Value != combos[b].Value {
			return combos[a].Value > combos[b].Value
		}
		return combos[a].Rule < combos[b].Rule
	})
	used := map[string]bool{}
	usedMembers := []ReportScoreItem{}
	total := 0.0
	for _, combo := range combos {
		conflict := false
		for _, id := range combo.EvidenceIDs {
			if used[id] {
				conflict = true
			}
			for _, member := range items {
				if member.ID == id {
					for _, prev := range usedMembers {
						if reportScoreDuplicate(member, prev) {
							conflict = true
						}
					}
				}
			}
		}
		if conflict {
			continue
		}
		combo.Value = math.Min(combo.Value, 1.5-total)
		if combo.Value <= 0 {
			continue
		}
		for _, id := range combo.EvidenceIDs {
			used[id] = true
			for _, member := range items {
				if member.ID == id {
					usedMembers = append(usedMembers, member)
				}
			}
		}
		c.Combinations = append(c.Combinations, combo)
		total += combo.Value
		c.Z += combo.Value
	}
	if c.HasBehavior {
		c.Cap = 79
	}
	for _, a := range direct {
		for _, d := range behaviors {
			if c.HasBehavior && reportScoreRelated(a, d) && reportScoreIndependent(a, d) && (p.kind != "exfiltration_related" && p.kind != "phishing_related" || reportScoreTransactionLinked(a, d)) {
				c.Cap = 94
			}
		}
	}
	if p.kind == "mining_related" || p.kind == "scanning_related" {
		c.Cap = math.Min(c.Cap, 79)
	}
	// Task authorization counters are applied only to the matching scope/material,
	// never as an unconditional "benign asset" discount.
	counterTotal := 0.0
	remainingPositive := map[int]float64{}
	for j, v := range c.Contributions {
		remainingPositive[j] = v.Value
	}
	counterSeen := []ReportScoreItem{}
	for _, counter := range items {
		if counter.X <= 0 || !reportScoreMatch(counter.Key, []string{"F_EXCL_SCAN_TASK", "F_EXCL_INFRA_ROLE"}) {
			continue
		}
		dup := false
		for _, prev := range counterSeen {
			if reportScoreDuplicate(counter, prev) {
				dup = true
			}
		}
		if dup {
			continue
		}
		covered := 0.0
		coveredRows := []int{}
		for j, positive := range c.Contributions {
			if strings.Contains(positive.Rule, "S:") || strings.Contains(positive.Rule, "I:") {
				continue
			}
			for _, i := range items {
				if i.ID == positive.EvidenceIDs[0] && reportScoreRelated(counter, i) && !reportScoreIndependent(counter, i) {
					covered += remainingPositive[j]
					coveredRows = append(coveredRows, j)
				}
			}
		}
		value := math.Min(covered, math.Min(1.2*counter.X, 2-counterTotal))
		if value > 0 {
			left := value
			for _, j := range coveredRows {
				part := math.Min(left, remainingPositive[j])
				remainingPositive[j] -= part
				left -= part
			}
			c.Counters = append(c.Counters, ReportScoreContribution{Rule: counter.Key, EvidenceIDs: []string{counter.ID}, Value: value, Reason: "verified_task_same_scope_and_source"})
			c.Z -= value
			counterTotal += value
			counterSeen = append(counterSeen, counter)
		}
	}
	c.Raw = 100 / (1 + math.Exp(-c.Z))
	c.Base = math.Min(c.Raw, c.Cap)
	return c
}

// Shared material establishes content linkage, not independent corroboration.
func reportScoreLinkedContent(a, b ReportScoreItem) bool {
	return reportScoreRelated(a, b) && !reportScoreIndependent(a, b) && len(a.Sources) > 0 && len(b.Sources) > 0
}

func fmtReportScoreInsufficient() error { return fmt.Errorf("report_score_without_effective_evidence") }
func roundReportScore(value, cap float64) int {
	return int(math.Round(math.Max(0, math.Min(value, cap))))
}
func reportScoreModelProjection(s *ReportScoring) map[string]any {
	factors := []map[string]any{}
	for _, i := range s.Items {
		factors = append(factors, map[string]any{"id": i.ID, "key": i.Key, "strength": i.Strength, "reliability": i.Reliability, "binding": i.Binding, "x": i.X})
	}
	weights := []map[string]any{}
	for _, p := range reportScoreProfiles() {
		for rowIndex, r := range p.rows {
			present := []string{}
			for _, i := range s.Items {
				if reportScoreMatch(i.Key, r.keys) {
					present = append(present, i.Key)
				}
			}
			if len(present) > 0 {
				weights = append(weights, map[string]any{"type": p.kind, "row": rowIndex + 1, "keys": reportSortedUnique(present), "weight": r.weight, "cap": r.cap, "shared_cap_group": r.limit})
			}
		}
	}
	return map[string]any{"version": s.Version, "knowledge_version": s.KnowledgeVersion, "formula": s.Formula, "calculation_rules": reportScoreCalculationRules(), "factors": factors, "weights": weights, "candidates": s.Candidates, "selected_type": s.SelectedType, "baseline_integer": s.Final, "max_adjustment": 5, "nature": "heuristic_evidence_estimate_not_calibrated_probability"}
}

func reportScoreTypeBehavior(kind string, i ReportScoreItem) bool {
	switch kind {
	case "c2_related":
		return reportScoreMatch(i.Key, []string{"F_BEACON_PERIODIC", "F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW", "F_HTTP_ENDPOINT_REPEAT", "F_LONG_LOW_SESSION", "S:S01/c2.command_intent/", "S:S02/c2.command_exchange/", "S:S13/payload.decoded_intent/command", "S:S04/c2.dns_encoded_intent/"})
	case "botnet_related":
		return reportScoreMatch(i.Key, []string{"F_TIME_COORDINATION", "F_COORD_FANOUT"})
	case "scanning_related":
		return i.Key == "F_FANOUT_SINGLE_SRC" || i.Key == "F_PORT_SEQUENCE"
	case "phishing_related":
		return !strings.HasPrefix(i.Key, "S:") || i.Strength >= .6
	case "exfiltration_related":
		return i.Key == "S:S07/exfil.sensitive_upload/"
	default:
		return true
	}
}

// Restore all successful report instances before scoring; no fixed row/byte cap.
// Actual model budgets are checked after knowledge/background compaction.
func prepareReportV02Evidence(b ReportEvidenceBundle) ReportEvidenceBundle {
	b.SelectedIDs = nil
	for _, e := range b.Entries {
		if e.Status == "missing" || e.Status == "unavailable" || e.Status == "not_observed" {
			continue
		}
		if e.Semantic != nil && (e.Semantic.DuplicateOf != "" || e.Semantic.Judgement == "neutral") {
			continue
		}
		b.SelectedIDs = append(b.SelectedIDs, e.ID)
	}
	b.Essence = nil
	e := buildReportEssence(b)
	// Old essence binds S explanations into F items. Keep v0.2 content slots
	// individually addressable so their actual implementation keys can be scored.
	kept := map[string]bool{}
	for j := range e.Items {
		kept[e.Items[j].ID] = true
		e.Items[j].Interpretations = nil
	}
	selected := map[string]bool{}
	for _, id := range b.SelectedIDs {
		selected[id] = true
	}
	for _, entry := range b.Entries {
		if entry.Semantic == nil || kept[entry.ID] || !selected[entry.ID] {
			continue
		}
		detail := ReportEssenceDetail{ID: fmt.Sprintf("D%03d", len(e.Details)+1), Statements: []string{entry.Semantic.Explanation}}
		for _, q := range entry.Semantic.Quotes {
			detail.Statements = append(detail.Statements, q.Excerpt)
		}
		e.Details = append(e.Details, detail)
		role := "background"
		if !entry.Semantic.ExplanationOnly && entry.Semantic.Judgement == "support" {
			role = "support"
		}
		e.Items = append(e.Items, ReportEssence{ID: entry.ID, Name: entry.Name, Summary: entry.Semantic.Explanation, Role: role, Scope: entry.Scope, Window: entry.Window, Details: []string{detail.ID}})
		e.Trace = append(e.Trace, ReportEssenceTrace{EntryID: entry.ID, EvidenceID: entry.ID, DetailID: detail.ID, Reason: "v02_stable_semantic_instance", SourceIDs: entry.SourceIDs})
	}
	sort.Slice(e.Items, func(i, j int) bool { return e.Items[i].ID < e.Items[j].ID })
	e.Version = "report-essence-v0.2"
	e.ProjectionOmitted = 0
	e.ProjectionByteBudget = 0
	b.Essence = &e
	b.SelectionOmitted = len(b.Entries) - len(b.SelectedIDs)
	return b
}

func reportScoreSameMeaning(a, b string) bool {
	if a == b {
		return true
	}
	groups := [][]string{
		{"F_DNS_ENCODED_LABEL", "F_HTTP_FIELD_ENCODING", "S:S01/c2.command_intent/", "S:S02/c2.command_exchange/", "S:S13/payload.decoded_intent/command", "S:S04/c2.dns_encoded_intent/"},
		{"F_BEACON_PERIODIC", "F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW", "F_HIST_SCHEDULE_MATCH", "O:schedule"},
		{"F_MULTI_DAY_PERSIST", "F_HIST_ASSET_IOC_RECURRENCE"},
		{"F_URL_HOMOGLYPH", "F_URL_BRAND_SUBDOMAIN_TRICK", "F_BRAND_IMPOSTOR", "S:S05/phishing.deception/", "S:S12/phishing.deception/brand_semantic_impostor"},
		{"F_CRED_POST_STRUCTURE", "F_FORM_CROSSSITE", "S:S06/phishing.credential_action/"},
	}
	for _, g := range groups {
		if reportScoreMatch(a, g) && reportScoreMatch(b, g) {
			return true
		}
	}
	return false
}

func reportScoreTransactionLinked(a, b ReportScoreItem) bool {
	if reportScoreLinkedContent(a, b) {
		return true
	}
	for _, d := range append(append([]evidence.Dependency{}, a.Relations...), b.Relations...) {
		left, right := false, false
		for _, ref := range d.SourceIDs {
			for _, s := range a.Sources {
				if ref == s {
					left = true
				}
			}
			for _, s := range b.Sources {
				if ref == s {
					right = true
				}
			}
		}
		if left && right {
			return true
		}
	}
	return false
}

func reportScoreScopedCandidate(p reportScoreProfile, items []ReportScoreItem) ReportThreatScore {
	groups := map[string][]ReportScoreItem{}
	intel := []ReportScoreItem{}
	for _, i := range items {
		if strings.HasPrefix(i.Key, "I:") {
			intel = append(intel, i)
			continue
		}
		if i.Scope.EndpointID == "" {
			continue
		}
		identity := i.Scope.AssetID
		if p.kind == "botnet_related" {
			identity = i.Scope.GroupID
			if identity == "" {
				continue
			}
		}
		if identity == "" {
			continue
		}
		key := identity + "|" + i.Scope.DeviceID + "|" + i.Scope.EndpointID
		groups[key] = append(groups[key], i)
	}
	names := []string{}
	for key := range groups {
		names = append(names, key)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return reportScoreCandidate(p, intel)
	}
	best := ReportThreatScore{Base: -1}
	for _, key := range names {
		scoped := append(append([]ReportScoreItem{}, groups[key]...), intel...)
		c := reportScoreCandidate(p, scoped)
		if best.Base < 0 || (c.HasBehavior && !best.HasBehavior) || c.HasBehavior == best.HasBehavior && c.Base > best.Base {
			best = c
		}
	}
	return best
}

// Complete execution/mapping audit, separate from the compact model context.
func reportV02CatalogAudit(b ReportEvidenceBundle) []map[string]any {
	keys := []string{}
	names := map[string]string{}
	for _, d := range evidence.Definitions() {
		key := string(d.ID)
		keys = append(keys, key)
		names[key] = d.Description
	}
	for _, d := range evidence.SemanticDefinitions() {
		key := "S:" + d.Key.ID + "/" + d.Key.Target + "/" + d.Key.Subtype
		keys = append(keys, key)
	}
	out := []map[string]any{}
	for _, key := range keys {
		role := "explanation_only"
		weights := []map[string]any{}
		instances := []map[string]any{}
		for _, p := range reportScoreProfiles() {
			for _, r := range p.rows {
				if reportScoreMatch(key, r.keys) {
					role = "conditional_score"
					weights = append(weights, map[string]any{"type": p.kind, "weight": r.weight, "row_cap": r.cap})
				}
			}
		}
		if key == "F_EXCL_SCAN_TASK" || key == "F_EXCL_INFRA_ROLE" {
			role = "conditional_counter"
		}
		for _, e := range b.Entries {
			if reportImplementationKey(e) == key {
				instance := map[string]any{"id": e.ID, "status": e.Status}
				if e.Finding != nil {
					instance["quality"] = e.Finding.Quality
					instance["eligibility"] = e.Finding.Eligibility
					instance["limitations"] = e.Finding.Limitations
				}
				instances = append(instances, instance)
			}
		}
		out = append(out, map[string]any{"implementation_key": key, "name": names[key], "role": role, "weights": weights, "actual_instances": instances})
	}
	return out
}

// Explanation only: the backend remains the sole owner of arithmetic and limits.
func reportScoreCalculationRules() map[string]string {
	return map[string]string{
		"effective_strength": "x=strength×reliability×binding，范围0至1；使用后端给出的因子，不自行重判算法门槛。材料缺失不加分，也不是反证。",
		"single_and_row":     "单项=weight×x。先去重，再在同一评分行内将最强项全额计入，其他保留的独立项按35%计入；合计不超过该行cap。共享上限的行共同受限，不再次折减35%。",
		"deduplication":      "同一对象范围内，同源且同义的跨行主张只取最强项；同行来源重叠不重复计入。事实及其同义语义解释不作为两份独立证据。重复条目不等于证据增强。",
		"combination":        "组合=组合权重×min(成员x)×关联核验值；关联核验值为0或1，由后端核验主体、对象、时间及所需事务或群体关系。来源不重叠才可称独立，共享内容只能证明内容关联。按贡献降序保留组合，共享成员或同源成员的组合不叠加，组合合计最高1.5。实际触发值以candidates.combinations为准。",
		"counter":            "仅已核验且覆盖本次对象、时间与来源的任务授权反证可抵扣其覆盖的事实贡献；单项最多1.2×x，合计最多2，且不超过尚未抵扣的覆盖贡献。不直接抵扣语义内容、情报或组合贡献；缺材料不能扣分。",
		"baseline":           "z=-2.2+sum(contributions.value)+sum(combinations.value)-sum(counters.value)；raw=100/(1+exp(-z))；base=min(raw,cap)。贡献作用于z，不是直接增加同等百分点；-2.2是启发式初值，不是统计先验。",
		"caps":               "一般接触或情报背景上限59；有本类型行为特征上限79；核验的强直接证据与独立行为关联成立时最高94，钓鱼及外传还要求事务关联。扫描、挖矿当前最高79。上限不是保底分，低分不证明正常。",
		"type_selection":     "分别计算各威胁类型及NetworkActivity子类型，不相加或平均；默认从有类型行为的候选中选择最高基准，没有类型行为则为一般接触。模型改选须引用相应候选实际支持证据，使用该候选后端基准。",
		"final_adjustment":   "模型仅可依据未计分的application_identity或dns_connection_relation实际观测建议±5个百分点，提供delta、reason、evidence_ids及uncovered_context_key。重复计分、无效引用或越界调整采用0。final=round(clamp(base+accepted_delta,0,cap))，最终值由后端写入；这是启发式恶意倾向，未经概率校准。",
		"writing":            "用实际事实与关联解释结论，不在报告正文复述评分行、算法变量、上限或审计过程，也不另写一个自由估计概率。",
	}
}
