package service

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

func renderV13ReportMarkdown(doc ReportDocument) string {
	if doc.SchemaVersion == "evidence-report-1.0" {
		return renderLegacyReportMarkdown(doc)
	}
	var w bytes.Buffer
	a, b := doc.Assessment, doc.Evidence
	verdict := map[string]string{"suspicious": "可疑通联，建议核查", "likely_malicious": "证据支持恶意活动研判", "likely_benign": "现有证据支持正常业务解释", "insufficient": "已确认通联，按证据表开展核查"}[a.Verdict]
	probability := "暂不估计"
	if a.Probability != nil {
		probability = strconv.Itoa(*a.Probability) + "%"
	}
	fmt.Fprintf(&w, "【结论】%s；%s。威胁事件概率：%s。\n\n## 研判摘要\n\n判断命题：本次通信是否属于恶意活动。\n\n概率性质：基于当前证据的模型研判估计。\n\n%s\n\n", reportThreatTypeNames[a.ThreatType], verdict, probability, reportCell(a.ProbabilityReason))
	fmt.Fprintf(&w, "资产清单匹配：\n\n%s\n\n", doc.AssetSection)
	fmt.Fprint(&w, "## 实际发生的行为\n\n")
	for _, e := range b.Entries {
		if strings.HasPrefix(e.Family, "saved_activity:") || strings.HasPrefix(e.Family, "dns_connection:") {
			fmt.Fprintf(&w, "- %s：%s\n", e.ID, reportCell(e.Result))
		}
	}
	fmt.Fprint(&w, "\n## 事实证据与研判意义\n\n| 编号 | 证据项 | 核验结果 | 来源 | 研判意义 |\n| --- | --- | --- | --- | --- |\n")
	meanings := map[string]string{}
	for _, i := range a.Interpretations {
		meanings[i.EvidenceID] = i.Meaning
	}
	for _, id := range b.SelectedIDs {
		for _, e := range b.Entries {
			if e.ID == id {
				fmt.Fprintf(&w, "| %s | %s | %s | %s | %s |\n", id, reportCell(e.Name), reportCell(e.Result), reportCell(e.Source), reportCell(meanings[id]))
			}
		}
	}
	fmt.Fprint(&w, "\n## 判断与概率依据\n\n")
	for _, group := range []struct {
		name string
		rs   []ReportReason
	}{{"主要支持", a.Supporting}, {"反向事实", a.Opposing}, {"替代解释", a.Alternatives}} {
		if len(group.rs) == 0 {
			continue
		}
		fmt.Fprintf(&w, "### %s\n\n", group.name)
		if len(group.rs) == 0 {
			fmt.Fprint(&w, "本次未列入此类依据。\n\n")
		}
		for _, r := range group.rs {
			fmt.Fprintf(&w, "- %s：%s\n", strings.Join(r.EvidenceIDs, "、"), reportCell(r.Explanation))
		}
		fmt.Fprintln(&w)
	}
	fmt.Fprint(&w, "## 核查及处置建议\n\n")
	for _, action := range a.Actions {
		fmt.Fprintf(&w, "- %s：%s；目的：%s。\n", strings.Join(action.EvidenceIDs, "、"), reportCell(action.Action), reportCell(action.Purpose))
	}
	fmt.Fprint(&w, "\n## 技术附录：材料缺项与核验记录\n\n")
	for _, g := range a.Gaps {
		fmt.Fprintf(&w, "- %s\n", reportCell(g))
	}
	fmt.Fprintf(&w, "\n## 附录：证据核验概况\n\n报告版本：%d；快照版本：%d。\n\n事实检查（按规则与范围计数）：成立%d项，当前范围未满足%d项，材料不足%d项；正文省略%d条可展示证据。省略不等于未执行，材料不足不等于行为不存在。\n\n语义任务（按槽位与命题计数）：引用校验通过%d项，跳过%d项，不可用%d项，拒绝%d项。\n", doc.AnalysisVersion, b.SnapshotVersion, b.FactCounts["observed"], b.FactCounts["not_observed"], b.FactCounts["missing"], b.SelectionOmitted, b.SemanticCounts["accepted"], b.SemanticCounts["skipped"], b.SemanticCounts["unavailable"], b.SemanticCounts["rejected"])
	if b.Normalized.Version != "" {
		fmt.Fprintf(&w, "\n统一证据索引：%d个实例；正文使用%d项精华；完整状态、指标与来源仍保存在本版本报告中。\n", len(b.Normalized.Items), len(b.SelectedIDs))
	}
	if b.FactStatus != "evaluated" {
		fmt.Fprintf(&w, "\n事实引擎本次未发布计算结果，状态：%s；相关规则的未执行原因见完整检查清单。\n", reportCell(b.FactStatus))
	}
	if b.History != nil {
		fmt.Fprintf(&w, "\n平台历史检索：状态=%s，匹配%d条，排除%d条；诊断=%s。历史活动不等于同战役或独立恶意结论。\n", reportCell(b.History.Status), len(b.History.Rows), b.History.ExcludedCount, reportCell(b.History.Reason))
	}
	return w.String()
}
