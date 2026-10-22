package service

import (
	"sort"
	"strings"
)

type ReportKnowledgeSelection struct {
	Version      string                `json:"version"`
	Cards        []ReportKnowledgeCard `json:"cards"`
	EvidenceKeys []string              `json:"evidence_keys"`
	Common       []string              `json:"common_meanings"`
	Omitted      []string              `json:"omitted"`
}
type ReportKnowledgeCard struct {
	Type       string   `json:"type"`
	Background string   `json:"professional_characteristics"`
	Meanings   []string `json:"evidence_meanings"`
}

// Knowledge is compiled from the four repository cards, not read from a desktop path.
//
//go:generate python ../../../../tools/generate_report_knowledge.py
func selectReportKnowledge(b ReportEvidenceBundle) ReportKnowledgeSelection {
	selection := ReportKnowledgeSelection{Version: "KD-v0.2", Cards: []ReportKnowledgeCard{}, EvidenceKeys: []string{}, Omitted: []string{"unrelated_card_sections", "algorithm_implementation_details", "unexecuted_catalog"}}
	keys := map[string]bool{}
	entries := map[string]ReportEvidence{}
	for _, e := range b.Entries {
		entries[e.ID] = e
	}
	for _, i := range reportEssenceFor(b).Items {
		if e, ok := entries[i.ID]; ok {
			key := reportImplementationKey(e)
			keys[key] = true
			selection.EvidenceKeys = append(selection.EvidenceKeys, key)
		}
	}
	selection.EvidenceKeys = reportSortedUnique(selection.EvidenceKeys)
	for _, key := range selection.EvidenceKeys {
		switch key {
		case "I:ioc_background":
			selection.Common = append(selection.Common, "I：有来源的IOC关联背景；IP命中不等于本次请求对象恶意，不独立证明攻击成功。")
		case "O:schedule":
			selection.Common = append(selection.Common, "O时段：展示实际命中与工作时段的关系；默认08—20时只提供弱上下文，不能认定资产作息异常。")
		default:
			if strings.HasPrefix(key, "O:") {
				selection.Common = append(selection.Common, "O：已保存材料的对象、方向、数量、时间和载荷概览；普通端口及零载荷不单独证明恶意。")
			}
		}
	}
	selection.Common = reportSortedUnique(selection.Common)
	active := map[string]bool{"NetworkActivity": true}
	if b.Scoring != nil {
		for _, c := range b.Scoring.Candidates {
			if c.HasBehavior || c.Type == b.Scoring.SelectedType {
				active[reportKnowledgeType(c.Type)] = true
			}
		}
	}
	names := []string{}
	for n := range active {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		text := reportKnowledgeSources[name]
		start := strings.Index(text, "## 总体专业特征")
		end := strings.Index(text, "## 实际F/S/I/O")
		card := ReportKnowledgeCard{Type: name, Meanings: []string{}}
		if start >= 0 && end > start {
			card.Background = strings.TrimSpace(text[start+len("## 总体专业特征") : end])
		}
		for _, line := range strings.Split(text, "\n") {
			if !strings.HasPrefix(line, "| `") {
				continue
			}
			cells := strings.Split(line, "|")
			if len(cells) < 4 {
				continue
			}
			key := strings.Trim(strings.TrimSpace(cells[1]), "`")
			lookup := key
			if !strings.HasPrefix(key, "F_") {
				parts := strings.Split(key, " / ")
				if len(parts) != 3 {
					continue
				}
				if parts[2] == "空" {
					parts[2] = ""
				}
				lookup = "S:" + strings.Join(parts, "/")
			}
			if keys[lookup] {
				card.Meanings = append(card.Meanings, strings.Join(cells[1:len(cells)-1], " | "))
			}
		}
		selection.Cards = append(selection.Cards, card)
	}
	// Meanings may live in a different card from a candidate's background.
	for _, name := range []string{"Botnet", "C2", "Phishing", "NetworkActivity"} {
		if active[name] {
			continue
		}
		card := ReportKnowledgeCard{Type: name, Meanings: []string{}}
		for _, line := range strings.Split(reportKnowledgeSources[name], "\n") {
			for key := range keys {
				match := strings.TrimPrefix(key, "S:")
				parts := strings.Split(match, "/")
				if len(parts) == 3 {
					if parts[2] == "" {
						parts[2] = "空"
					}
					match = strings.Join(parts, " / ")
				}
				if strings.HasPrefix(line, "| `"+match+"` |") {
					card.Meanings = append(card.Meanings, line)
					break
				}
			}
		}
		if len(card.Meanings) > 0 {
			selection.Cards = append(selection.Cards, card)
		}
	}
	return selection
}
func reportKnowledgeType(kind string) string {
	switch kind {
	case "c2_related":
		return "C2"
	case "botnet_related":
		return "Botnet"
	case "phishing_related":
		return "Phishing"
	default:
		return "NetworkActivity"
	}
}

func applyReportScoring(a *ReportAssessment, b ReportEvidenceBundle) error {
	if b.Scoring == nil {
		return nil
	}
	s := *b.Scoring
	s.Adjustment = ReportScoreAdjustment{Proposed: a.ModelAdjustment, Reason: "no_eligible_adjustment"}
	if !s.HasEvidence {
		return fmtReportScoreInsufficient()
	}
	selected := s.SelectedType
	// A model can choose only another already computed, supported candidate.
	for _, c := range s.Candidates {
		if c.Type == a.ThreatType && c.HasBehavior && reportModelReferencesCandidate(*a, c) {
			selected = c.Type
			break
		}
	}
	var candidate ReportThreatScore
	for _, c := range s.Candidates {
		if c.Type == selected {
			candidate = c
			break
		}
	}
	if adj := a.ModelAdjustment; adj != nil && adj.Invalid == "" && adj.Delta >= -5 && adj.Delta <= 5 && len(adj.Reason) > 0 && len(adj.EvidenceIDs) > 0 {
		used := map[string]bool{}
		for _, v := range candidate.Contributions {
			for _, id := range v.EvidenceIDs {
				used[id] = true
			}
		}
		for _, v := range candidate.Combinations {
			for _, id := range v.EvidenceIDs {
				used[id] = true
			}
		}
		allowed := map[string]bool{}
		for _, item := range reportEssenceFor(b).Items {
			allowed[item.ID] = true
		}
		valid := true
		seen := map[string]bool{}
		for _, id := range adj.EvidenceIDs {
			if !allowed[id] || used[id] || seen[id] {
				valid = false
				break
			}
			seen[id] = true
			found := false
			for _, e := range b.Entries {
				if e.ID != id {
					continue
				}
				key := ""
				switch e.Feature {
				case "application_fields":
					key = "application_identity"
				case "dns_connection":
					key = "dns_connection_relation"
				}
				if key != "" && key == adj.ContextKey && e.Status == "observed" && len(e.SourceIDs) > 0 {
					found = true
				}
			}
			if !found {
				valid = false
			}
		}
		if valid {
			s.Adjustment.AcceptedDelta = adj.Delta
			s.Adjustment.Reason = "verified_unscored_observation_context"
		}
	}
	s.SelectedType = selected
	s.Final = roundReportScore(candidate.Base+float64(s.Adjustment.AcceptedDelta), candidate.Cap)
	a.ThreatType = selected
	if s.Final >= 80 {
		a.Verdict = "likely_malicious"
	} else if s.Final <= 20 && len(candidate.Counters) > 0 {
		a.Verdict = "likely_benign"
	} else {
		a.Verdict = "suspicious"
	}
	a.Probability = &s.Final
	a.Scoring = &s
	return nil
}

func reportModelReferencesCandidate(a ReportAssessment, c ReportThreatScore) bool {
	cited := map[string]bool{}
	for _, r := range a.Supporting {
		for _, id := range r.EvidenceIDs {
			cited[id] = true
		}
	}
	for _, v := range c.Contributions {
		if strings.Contains(v.Rule, "I:") {
			continue
		}
		for _, id := range v.EvidenceIDs {
			if cited[id] {
				return true
			}
		}
	}
	return false
}
