package evidence

import (
	"math"
	"sort"
	"strings"
)

func completeHistoryProof(p Provenance) bool { return provenance(p) && p.Complete }

func stageLevel(stage string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(stage)) {
	case "scan", "exploit":
		return 1, true
	case "c2":
		return 2, true
	case "exfil":
		return 3, true
	}
	return 0, false
}

func stageSourceAccepted(source string) bool {
	return source == "hard_facts" || source == "human" || source == "host_evidence" || source == "authoritative_external"
}

// A known campaign conflict cannot be overridden by a shared IOC. Campaign
// rotation is allowed only with independently verified membership on both sides.
func stageHistoryBinding(h *HistoryData, r HistoryEvent) (bool, ReasonCode) {
	if h.CampaignID != "" {
		if r.CampaignID == "" || !completeHistoryProof(r.CampaignProvenance) {
			return false, UnresolvedBinding
		}
		return r.CampaignID == h.CampaignID, ""
	}
	if r.IOC == "" {
		return false, UnresolvedBinding
	}
	if r.IOC == h.IOC && r.CampaignID != "" && !completeHistoryProof(r.CampaignProvenance) {
		return false, UnresolvedBinding
	}
	return r.IOC == h.IOC, ""
}

func historyRowRefs(r HistoryEvent) []string {
	refs := []string{r.ID}
	if r.AdjudicationID != "" {
		refs = append(refs, r.AdjudicationID)
	}
	return refs
}

func (e *Engine) stageProgression(f Finding, g *observations, h *HistoryData) Finding {
	current, ok := stageLevel(h.CurrentStage)
	if !ok || !stageSourceAccepted(h.CurrentStageSource) || !completeHistoryProof(h.CurrentStageProvenance) {
		return absent(f, MissingInput)
	}
	if h.IOC == "" && h.CampaignID == "" {
		return absent(f, UnresolvedBinding)
	}
	if h.CampaignID != "" && !completeHistoryProof(h.CampaignProvenance) {
		return absent(f, UnresolvedBinding)
	}
	if h.Endpoint != "" && h.Endpoint != g.scope.EndpointID {
		return absent(f, UnresolvedBinding)
	}
	dependency(&f, "current_stage", h.CurrentStageProvenance)
	refs := append(append([]string(nil), h.SourceIDs...), h.CurrentStageProvenance.SourceIDs...)
	if h.CampaignID != "" {
		dependency(&f, "current_campaign", h.CampaignProvenance)
		refs = append(refs, h.CampaignProvenance.SourceIDs...)
	}
	stages := []HistoryEvent{}
	historicalCampaign := ""
	for _, r := range h.Events {
		if r.AssetID != g.scope.AssetID {
			continue
		}
		// Authoritatively reviewed benign events supply no attack phase and
		// must not be stitched into the chain or its campaign consistency check.
		if reviewed(r) && r.Adjudication == "false_positive" {
			continue
		}
		bound, reason := stageHistoryBinding(h, r)
		if reason != "" {
			return absent(f, reason)
		}
		if !bound {
			continue
		}
		if r.CampaignID != "" {
			if historicalCampaign != "" && historicalCampaign != r.CampaignID {
				return absent(f, UnresolvedBinding)
			}
			historicalCampaign = r.CampaignID
		}
		if !reviewed(r) {
			return absent(f, MissingInput)
		}
		if _, valid := stageLevel(r.Stage); !valid {
			return absent(f, MissingInput)
		}
		if !r.Time.Before(g.times[0]) {
			return absent(f, UnresolvedBinding)
		}
		stages = append(stages, r)
		refs = append(refs, historyRowRefs(r)...)
		if r.CampaignID != "" {
			dependency(&f, "historical_campaign", r.CampaignProvenance)
			refs = append(refs, r.CampaignProvenance.SourceIDs...)
		}
	}
	sort.Slice(stages, func(i, j int) bool { return stages[i].Time.Before(stages[j].Time) })
	previous, monotonic := 0, true
	for i, r := range stages {
		level, _ := stageLevel(r.Stage)
		if i > 0 && stages[i-1].Time.Equal(r.Time) {
			old, _ := stageLevel(stages[i-1].Stage)
			if old != level {
				return absent(f, UnresolvedBinding)
			}
		}
		if previous > level {
			monotonic = false
		}
		previous = level
	}
	// Historical advancement alone is insufficient: the current stage must
	// advance beyond the latest bound historical stage, with no regression.
	progression := len(stages) > 0 && monotonic && current > previous
	f.Measurements.Labels = []string{"current_stage:" + strings.ToLower(strings.TrimSpace(h.CurrentStage))}
	f.Limitations = append(f.Limitations, "仅说明同资产、同IOC或核验战役内的阶段时序推进；当前阶段必须高于最近历史阶段；不证明因果攻击链或攻击成功")
	return finish(f, progression, map[string]float64{"adjudicated_stages": float64(len(stages)), "current_stage_level": float64(current), "latest_historical_stage_level": float64(previous)}, refs...)
}

func validCompleteMembers(ids []string, min int) bool {
	if len(ids) < min {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" || id != strings.TrimSpace(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func containsHistoryMember(ids []string, assetID string) bool {
	for _, id := range ids {
		if id == assetID {
			return true
		}
	}
	return false
}

// Infrastructure matching is conjunctive for every supplied identity. Family
// labels cannot replace an actual IOC/endpoint, or override an explicit conflict.
func coordinationHistoryBinding(h *HistoryData, r HistoryEvent) (bool, ReasonCode) {
	if (h.IOC != "" && r.IOC != "" && h.IOC != r.IOC) || (h.Endpoint != "" && r.Endpoint != "" && h.Endpoint != r.Endpoint) {
		return false, ""
	}
	if r.CampaignID == "" || !completeHistoryProof(r.CampaignProvenance) {
		return false, UnresolvedBinding
	}
	if h.CampaignID != r.CampaignID {
		return false, ""
	}
	if (h.IOC != "" && r.IOC == "") || (h.Endpoint != "" && r.Endpoint == "") {
		return false, UnresolvedBinding
	}
	if h.GroupID != "" {
		if !r.GroupMembershipVerified || !validCompleteMembers(r.MemberIDs, 3) {
			return false, UnresolvedBinding
		}
		if r.AssetID != "" && !containsHistoryMember(r.MemberIDs, r.AssetID) {
			return false, UnresolvedBinding
		}
		if !sameSet(h.CurrentMemberIDs, r.MemberIDs) {
			return false, ""
		}
	}
	return true, ""
}

func (e *Engine) coordinationHistoryMatch(f Finding, g *observations, h *HistoryData) Finding {
	if !h.CurrentParametersVerified || len(h.CurrentParameters) == 0 {
		return absent(f, MissingInput)
	}
	for key, value := range h.CurrentParameters {
		if strings.TrimSpace(key) == "" || !finite(value) {
			return absent(f, MissingInput)
		}
	}
	if (h.IOC == "" && h.Endpoint == "") || h.CampaignID == "" || !completeHistoryProof(h.CampaignProvenance) {
		return absent(f, UnresolvedBinding)
	}
	if h.Endpoint != "" && h.Endpoint != g.scope.EndpointID {
		return absent(f, UnresolvedBinding)
	}
	if h.GroupID != "" && (!h.GroupMembershipVerified || !validCompleteMembers(h.CurrentMemberIDs, 3) || !containsHistoryMember(h.CurrentMemberIDs, g.scope.AssetID)) {
		return absent(f, UnresolvedBinding)
	}
	tolerance, ok := e.policy(&f, "parameter_relative_tolerance")
	if !ok || tolerance < 0 {
		return absent(f, MissingPolicy)
	}
	dependency(&f, "current_campaign", h.CampaignProvenance)
	refs := append(append([]string(nil), h.SourceIDs...), h.CampaignProvenance.SourceIDs...)
	boundEvents, matches, malicious, benign := 0, 0, 0, 0
	for _, r := range h.Events {
		if h.GroupID != "" {
			if r.GroupID != h.GroupID {
				continue
			}
		} else if r.AssetID != g.scope.AssetID || r.GroupID != "" {
			continue
		}
		bound, reason := coordinationHistoryBinding(h, r)
		if reason != "" {
			return absent(f, reason)
		}
		if !bound {
			continue
		}
		if !reviewed(r) || len(r.Parameters) == 0 {
			return absent(f, MissingInput)
		}
		boundEvents++
		refs = append(refs, historyRowRefs(r)...)
		refs = append(refs, r.CampaignProvenance.SourceIDs...)
		dependency(&f, "historical_campaign", r.CampaignProvenance)
		match := true
		for k, v := range h.CurrentParameters {
			old, exists := r.Parameters[k]
			if !exists || !finite(old) {
				return absent(f, MissingInput)
			}
			if math.Abs(v-old)/math.Max(math.Abs(old), 1e-9) > tolerance {
				match = false
			}
		}
		if match {
			matches++
			if r.Adjudication == "malicious" {
				malicious++
			} else {
				benign++
			}
		}
	}
	f.Limitations = append(f.Limitations, "仅说明同基础设施、核验战役及相同作用范围内的参数相似；群体须完整成员集合一致；不从参数接近推断同战役、感染或攻击成功，定谳结果分别记录")
	return finish(f, matches > 0, map[string]float64{"matching_adjudicated_parameters": float64(matches), "bound_historical_events": float64(boundEvents), "malicious_parameter_matches": float64(malicious), "false_positive_parameter_matches": float64(benign)}, refs...)
}
