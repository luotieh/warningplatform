package service

import (
	"fmt"
	"strings"
	"vulnscan-backend/evidence"
)

// Relative influence is an interpretation instruction, not arithmetic points
// or a calibrated probability. It never changes alert severity/IOC scores.
func reportWeightPolicy(b ReportEvidenceBundle) map[string]any {
	items := []map[string]any{}
	for _, e := range b.Entries {
		if e.Family == "saved_schedule" && e.Status == "observed" {
			items = append(items, map[string]any{"evidence_id": e.ID, "relative_influence": 1.15, "dependency_group": "temporal:" + scopeKey(e.Scope), "rule": "实际非工作时段/跨日记录作为辅助依据；默认时段不证明实际作息；与同范围时间算法和SC01不重复叠加；已证实全天运行或授权业务优先解释。"})
		}
		if e.Finding == nil || e.Finding.Status != evidence.Observed || e.Finding.Eligibility != "eligible" {
			continue
		}
		switch e.FactID {
		case evidence.BeaconPeriodic, "F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW", evidence.MultiDayPersist:
			items = append(items, map[string]any{"evidence_id": e.ID, "relative_influence": 1.25, "dependency_group": "temporal:" + scopeKey(e.Scope), "rule": "同范围时间规律取最强依据，禁止叠加；须结合业务任务和作息替代解释，不单独证明恶意。"})
		}
	}
	return map[string]any{"version": "report-weights-1.4", "enhanced_temporal": items, "ordinary_relative_influence": 1.0, "night_access": "默认北京时间08:00—20:00为比较时段，不强制资产角色；实际非工作时段记录可作辅助依据，不能写成已核验作息异常；已配置专用时段优先，全天运行和授权业务优先解释。", "high_probability": "80至90必须有恶意内容/指令/凭据/异常传输等直接证据，并有独立行为或关联证据支持；单一情报、TLS接触或时间规律不能支持该区间。", "no_floor": true, "probability_nature": "证据约束的模型研判估计，不是统计校准概率；禁止将相对影响直接换算百分比。"}
}

func validateHighReportProbability(a ReportAssessment, entries map[string]ReportEvidence) error {
	if a.Probability == nil || *a.Probability < 80 {
		return nil
	}
	direct := false
	behaviorGroups := map[string]bool{}
	for _, r := range a.Supporting {
		for _, id := range r.EvidenceIDs {
			e := entries[id]
			if e.Semantic != nil && !e.Semantic.ExplanationOnly && e.Semantic.Judgement == "support" && e.Semantic.Strength == "strong" {
				switch e.Semantic.Slot.ID {
				case "S01", "S02", "S05", "S06", "S07", "S09", "S10", "S11", "S13":
					direct = true
					behaviorGroups["content"] = true
				}
			}
			if e.Finding != nil && e.Status == "observed" && e.Finding.Eligibility == "eligible" {
				group := string(e.FactID)
				if strings.Contains(group, "BEACON") || strings.Contains(group, "DAILY") || strings.Contains(group, "MULTI_DAY") {
					group = "temporal"
				}
				behaviorGroups[group] = true
			}
		}
	}
	if !direct || len(behaviorGroups) < 2 {
		return fmt.Errorf("report_high_probability_without_direct_and_independent_behavior")
	}
	return nil
}
