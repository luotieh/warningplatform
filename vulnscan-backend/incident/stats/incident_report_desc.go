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
