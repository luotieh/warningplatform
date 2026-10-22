package service

import (
	"fmt"
	"sort"
	"strings"
)

// Only documents carrying a backend v0.2 score take this path. Saved layouts
// remain immutable, including their appendix checks during export.
func renderReportV02(doc ReportDocument) string {
	a, b := doc.Assessment, doc.Evidence
	var w strings.Builder
	verdict := map[string]string{"suspicious": "可疑通联", "likely_malicious": "较可能属于恶意活动", "likely_benign": "正常业务倾向", "insufficient": "需要核查通信归属"}[a.Verdict]
	fmt.Fprintf(&w, "## 一、研判结论\n\n本次事件判断为%s，研判恶意倾向：%d%%。\n\n%s\n\n", verdict, a.Scoring.Final, reportCell(a.ProbabilityReason))
	w.WriteString(renderCompactEventOverview(doc))
	// Keep low-level packet facts in the overview, not as extra malicious evidence.
	for _, e := range b.Entries {
		if e.Feature == "saved_activity" {
			samples, ok := reportScoreNumber(e.Measurements["payload_samples"])
			bytes, known := reportScoreNumber(e.Measurements["payload_total_bytes"])
			if ok && known && samples > 0 {
				fmt.Fprintf(&w, "\n已核验应用载荷：%.0f份报文，共%.0f字节，仅对应这些报文。\n", samples, bytes)
			}
		}
	}
	w.WriteString("\n## 三、关键证据\n\n")
	entries := map[string]ReportEvidence{}
	for _, e := range b.Entries {
		entries[e.ID] = e
	}
	meanings := map[string]string{}
	for _, m := range a.Interpretations {
		meanings[m.EvidenceID] = m.Meaning
	}
	importance := map[string]float64{}
	for _, c := range a.Scoring.Candidates {
		if c.Type == a.Scoring.SelectedType {
			for _, v := range append(append([]ReportScoreContribution{}, c.Contributions...), c.Combinations...) {
				for _, id := range v.EvidenceIDs {
					importance[id] += v.Value
				}
			}
		}
	}
	items := append([]ReportEssence{}, reportEssenceFor(b).Items...)
	sort.SliceStable(items, func(i, j int) bool {
		if importance[items[i].ID] != importance[items[j].ID] {
			return importance[items[i].ID] > importance[items[j].ID]
		}
		return items[i].ID < items[j].ID
	})
	number := 0
	for _, item := range items {
		e := entries[item.ID]
		if e.Kind == "observation" && e.Feature != "schedule" {
			continue
		}
		if e.Kind == "semantic" && !reportV02ContentSemantic(a.Scoring, item.ID) {
			continue
		}
		if e.FactID == "F_SMALL_PACKET" {
			continue
		}
		if e.Status == "missing" || e.Status == "not_observed" || e.Status == "unavailable" {
			continue
		}
		text := meanings[item.ID]
		if text == "" {
			text = item.Summary
		}
		number++
		fmt.Fprintf(&w, "%d. **%s %s**：%s。\n\n", number, item.ID, reportCell(item.Name), strings.TrimRight(reportCell(text), "。"))
	}
	if number == 0 {
		w.WriteString("已保存的通联对象及情报来源见事件总览。\n\n")
	}
	w.WriteString("## 四、风险分析\n\n")
	for _, r := range a.Risks {
		fmt.Fprintf(&w, "- %s（依据：%s）。\n\n", strings.TrimRight(reportCell(r.Impact), "。"), strings.Join(r.EvidenceIDs, "、"))
	}
	w.WriteString("## 五、处置建议\n\n")
	for j, action := range a.Actions {
		fmt.Fprintf(&w, "%d. %s；%s（依据：%s）。\n\n", j+1, strings.TrimRight(reportCell(action.Action), "。"), strings.TrimRight(reportCell(action.Purpose), "。"), strings.Join(action.EvidenceIDs, "、"))
	}
	return w.String()
}

func reportV02ContentSemantic(s *ReportScoring, id string) bool {
	for _, item := range s.Items {
		if item.ID == id {
			return item.Strength > 0
		}
	}
	return false
}
