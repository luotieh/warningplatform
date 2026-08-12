package stats

import (
	"fmt"
	"strings"

	statsContract "vulnscan-backend/incident/stats/stats-contract"
)

// ReportDescriptionBlock 导出报告中的描述小节（序号按实际有内容的小节连续编号）。
type ReportDescriptionBlock struct {
	Title string
	Body  string
}

var reportSectionLabels = []struct {
	key  string
	body func(statsContract.IncidentReportDescriptionSections) string
}{
	{"事件成因", func(s statsContract.IncidentReportDescriptionSections) string { return s.Cause }},
	{"证据详情", func(s statsContract.IncidentReportDescriptionSections) string { return s.Evidence }},
	{"详细证据", func(s statsContract.IncidentReportDescriptionSections) string { return s.Detail }},
	{"溯源信息", func(s statsContract.IncidentReportDescriptionSections) string { return s.Trace }},
}

var chineseOrdinal = []string{"一", "二", "三", "四", "五", "六"}

func reportDescriptionBlocks(data *statsContract.IncidentReportData) []ReportDescriptionBlock {
	if data == nil {
		return nil
	}
	if data.DescriptionSections.HasSections {
		var blocks []ReportDescriptionBlock
		idx := 0
		for _, sec := range reportSectionLabels {
			body := strings.TrimSpace(sec.body(data.DescriptionSections))
			if body == "" {
				continue
			}
			title := sec.key
			if idx < len(chineseOrdinal) {
				title = fmt.Sprintf("%s、%s", chineseOrdinal[idx], sec.key)
			}
			blocks = append(blocks, ReportDescriptionBlock{Title: title, Body: body})
			idx++
		}
		return blocks
	}
	desc := strings.TrimSpace(data.Description)
	if desc == "" {
		return nil
	}
	return []ReportDescriptionBlock{{Title: "隐患描述", Body: desc}}
}

// reportAnalysisBlocks 安全事件分析报告扩展章节（事件概述/流量证据与IOC/影响评估/
// 处置行动/附件清单），仅渲染非空章节。
func reportAnalysisBlocks(data *statsContract.IncidentReportData) []ReportDescriptionBlock {
	if data == nil {
		return nil
	}
	var blocks []ReportDescriptionBlock

	if strings.TrimSpace(data.CoreConclusion) != "" {
		blocks = append(blocks, ReportDescriptionBlock{Title: "事件概述", Body: data.CoreConclusion})
	}

	var evidence strings.Builder
	for _, ev := range data.TrafficEvidence {
		fmt.Fprintf(&evidence, "证据类型：%s\n", dashIfEmpty(ev.Type))
		if strings.TrimSpace(ev.Detail) != "" {
			fmt.Fprintf(&evidence, "技术细节：%s\n", ev.Detail)
		}
		if strings.TrimSpace(ev.Source) != "" {
			fmt.Fprintf(&evidence, "证据来源：%s\n", ev.Source)
		}
		if ev.Confidence > 0 || strings.TrimSpace(ev.ConfidenceText) != "" {
			fmt.Fprintf(&evidence, "置信度：%s (%d%%)\n", dashIfEmpty(ev.ConfidenceText), ev.Confidence)
		}
		evidence.WriteString("\n")
	}
	for _, ioc := range data.Iocs {
		fmt.Fprintf(&evidence, "IOC类型：%s\n", dashIfEmpty(ioc.Type))
		fmt.Fprintf(&evidence, "IOC值：%s\n", dashIfEmpty(ioc.Value))
		if strings.TrimSpace(ioc.ThreatSource) != "" {
			fmt.Fprintf(&evidence, "威胁情报来源：%s\n", ioc.ThreatSource)
		}
		if strings.TrimSpace(ioc.Match) != "" {
			fmt.Fprintf(&evidence, "匹配结果：%s\n", ioc.Match)
		}
		evidence.WriteString("\n")
	}
	if strings.TrimSpace(data.IocValidity) != "" {
		fmt.Fprintf(&evidence, "IOC有效性说明：%s\n", data.IocValidity)
	}
	if strings.TrimSpace(evidence.String()) != "" {
		blocks = append(blocks, ReportDescriptionBlock{
			Title: "流量证据与IOC明细",
			Body:  strings.TrimRight(evidence.String(), "\n"),
		})
	}

	var impact strings.Builder
	if strings.TrimSpace(data.Impact.Business) != "" {
		fmt.Fprintf(&impact, "业务影响：%s\n", data.Impact.Business)
	}
	if strings.TrimSpace(data.Impact.DataRisk) != "" {
		fmt.Fprintf(&impact, "数据风险：%s\n", data.Impact.DataRisk)
	}
	if strings.TrimSpace(data.Impact.Intent) != "" {
		fmt.Fprintf(&impact, "攻击意图：%s\n", data.Impact.Intent)
	}
	if strings.TrimSpace(impact.String()) != "" {
		blocks = append(blocks, ReportDescriptionBlock{Title: "影响评估", Body: strings.TrimRight(impact.String(), "\n")})
	}

	var actions strings.Builder
	if len(data.ImmediateActions) > 0 {
		actions.WriteString("立即行动项（30分钟内完成）：\n")
		for i, a := range data.ImmediateActions {
			fmt.Fprintf(&actions, "%d. %s\n", i+1, a.Action)
			if strings.TrimSpace(a.Detail) != "" {
				fmt.Fprintf(&actions, "   - %s\n", a.Detail)
			}
		}
		actions.WriteString("\n")
	}
	if len(data.FollowupActions) > 0 {
		actions.WriteString("后续处置项（24小时内完成）：\n")
		for i, a := range data.FollowupActions {
			fmt.Fprintf(&actions, "%d. %s\n", i+1, a.Action)
			if strings.TrimSpace(a.Detail) != "" {
				fmt.Fprintf(&actions, "   - %s\n", a.Detail)
			}
		}
	}
	if strings.TrimSpace(actions.String()) != "" {
		blocks = append(blocks, ReportDescriptionBlock{Title: "处置建议", Body: strings.TrimRight(actions.String(), "\n")})
	}

	var attachments strings.Builder
	for _, at := range data.Attachments {
		fmt.Fprintf(&attachments, "- %s", dashIfEmpty(at.Name))
		if strings.TrimSpace(at.Path) != "" {
			fmt.Fprintf(&attachments, "：%s", at.Path)
		}
		attachments.WriteString("\n")
	}
	if strings.TrimSpace(attachments.String()) != "" {
		blocks = append(blocks, ReportDescriptionBlock{Title: "附件清单", Body: strings.TrimRight(attachments.String(), "\n")})
	}
	return blocks
}

func dashIfEmpty(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

const (
	sectionCause    = "【事件成因】"
	sectionEvidence = "【证据详情】"
	sectionDetail   = "【详细证据】"
	sectionTrace    = "【溯源信息】"
)

func parseIncidentDescriptionSections(text string) statsContract.IncidentReportDescriptionSections {
	raw := strings.TrimSpace(text)
	if raw == "" {
		return statsContract.IncidentReportDescriptionSections{}
	}
	if !strings.Contains(raw, sectionCause) {
		return statsContract.IncidentReportDescriptionSections{}
	}
	hasDetail := strings.Contains(raw, sectionDetail)
	evidenceEnd := sectionTrace
	if hasDetail {
		evidenceEnd = sectionDetail
	}
	return statsContract.IncidentReportDescriptionSections{
		HasSections: true,
		Cause:       extractBetweenSection(raw, sectionCause, sectionEvidence),
		Evidence:    extractBetweenSection(raw, sectionEvidence, evidenceEnd),
		Detail:      extractBetweenSection(raw, sectionDetail, sectionTrace),
		Trace:       extractBetweenSection(raw, sectionTrace, ""),
	}
}

func extractBetweenSection(text, startMark, endMark string) string {
	start := strings.Index(text, startMark)
	if start < 0 {
		return ""
	}
	body := text[start+len(startMark):]
	if endMark != "" {
		if end := strings.Index(body, endMark); end >= 0 {
			body = body[:end]
		}
	}
	return strings.TrimSpace(body)
}

func extractMonitorExecutionID(text string) string {
	for _, mark := range []string{"监测执行 ID：", "监测执行 ID:"} {
		if idx := strings.Index(text, mark); idx >= 0 {
			rest := strings.TrimSpace(text[idx+len(mark):])
			if rest == "" {
				continue
			}
			end := strings.IndexAny(rest, "\n\r\t ")
			if end > 0 {
				return strings.TrimSpace(rest[:end])
			}
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
