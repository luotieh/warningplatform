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
	w.WriteString(renderEventOverview(doc, true))
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
		fmt.Fprintf(&w, "%d. **%s**：%s。\n\n", number, reportCell(reportV02EvidenceTitle(e, item.Name)), strings.TrimRight(reportCell(text), "。"))
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

func reportV02EvidenceTitle(e ReportEvidence, fallback string) string {
	titles := map[string]string{"F_BEACON_PERIODIC": "周期通信", "F_BEACON_JITTER": "抖动周期通信", "F_FIXED_DAILY_WINDOW": "每天固定时段通信", "F_MULTI_DAY_PERSIST": "跨日重复通信", "F_HIST_ASSET_IOC_RECURRENCE": "同资产同目标历史接触", "F_SMALL_PACKET": "低应用载荷占比"}
	if title := titles[string(e.FactID)]; title != "" {
		return title
	}
	if e.Kind == "intelligence" {
		return "IOC情报"
	}
	if e.Feature == "schedule" {
		return "非工作时段通信"
	}
	return strings.TrimPrefix(firstNonEmpty(fallback, "通信事实"), "语义解释：")
}

// Full immutable overview for v0.2; actual request budget checks run afterwards.
// Keep complete tuple counts and IOC fields rather than silently dropping rows.
func reportV02OverviewProjection(o ReportEventOverview) map[string]any {
	result := pipelineOverviewProjection(o)
	result["five_tuples"] = o.Tuples
	result["iocs"] = o.IOCs
	result["omitted_five_tuples"] = 0
	result["omitted_iocs"] = 0
	result["coverage_note"] = "all saved overview tuples and IOC fields retained; saved hits are not sessions"
	return result
}
