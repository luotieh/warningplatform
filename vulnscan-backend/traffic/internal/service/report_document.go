package service

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"

	"github.com/gomutex/godocx"
	"github.com/gomutex/godocx/wml/stypes"
)

func (s Services) ReportDocument(ctx context.Context, eventID string, summaryID int64) (ReportDocument, error) {
	summaries := s.Store.ListSummaries(eventID)
	if len(summaries) == 0 {
		return ReportDocument{}, fmt.Errorf("report_not_found")
	}
	summary := summaries[len(summaries)-1]
	if summaryID > 0 {
		found := false
		for _, item := range summaries {
			if item.ID == summaryID {
				summary = item
				found = true
				break
			}
		}
		if !found {
			return ReportDocument{}, fmt.Errorf("report_not_found")
		}
	}
	record, exists, err := s.Store.AggregateRecord(ctx, "report_document", reportDocumentKey(eventID, summary.ID))
	if err != nil {
		return ReportDocument{}, fmt.Errorf("report_document_read_failed")
	}
	if !exists {
		return ReportDocument{}, fmt.Errorf("legacy_report_without_evidence_document")
	}
	var doc ReportDocument
	if len(record.Value) > 16<<20 || json.Unmarshal(record.Value, &doc) != nil || doc.SummaryID != summary.ID || doc.EventID != eventID || doc.Markdown != summary.EventSummary || doc.SchemaVersion != reportEvidenceVersion || doc.AnalysisVersion != summary.Version || doc.Kind != summary.Kind {
		return ReportDocument{}, fmt.Errorf("report_document_binding_invalid")
	}
	if err := validateReportAssessment(doc.Assessment, doc.Evidence); err != nil {
		return ReportDocument{}, fmt.Errorf("stored_report_validation_failed")
	}
	if renderReportMarkdown(doc) != doc.Markdown {
		return ReportDocument{}, fmt.Errorf("stored_report_render_mismatch")
	}
	doc.SummaryID = summary.ID
	return doc, nil
}

// ReportDocumentForExport also supports saved reports predating evidence bundles.
func (s Services) ReportDocumentForExport(ctx context.Context, eventID string, summaryID int64) (ReportDocument, error) {
	summaries := s.Store.ListSummaries(eventID)
	if len(summaries) == 0 {
		return ReportDocument{}, fmt.Errorf("report_not_found")
	}
	summary := summaries[len(summaries)-1]
	if summaryID > 0 {
		found := false
		for _, item := range summaries {
			if item.ID == summaryID {
				summary = item
				found = true
				break
			}
		}
		if !found {
			return ReportDocument{}, fmt.Errorf("report_not_found")
		}
	}
	// Pin the resolved version before reading its bundle.
	doc, err := s.ReportDocument(ctx, eventID, summary.ID)
	if err == nil || err.Error() != "legacy_report_without_evidence_document" {
		return doc, err
	}
	if strings.TrimSpace(summary.EventSummary) == "" {
		return ReportDocument{}, fmt.Errorf("report_not_found")
	}
	return ReportDocument{EventID: eventID, SummaryID: summary.ID, Title: "安全事件研判报告", Markdown: summary.EventSummary, AnalysisVersion: summary.Version, Kind: summary.Kind, CreatedAt: summary.CreatedAt}, nil
}

func (s Services) saveReportDocument(ctx context.Context, doc ReportDocument, roundID int) (summary domain.Summary, err error) {
	err = s.Store.AggregationTransaction(ctx, "report-"+doc.EventID, func(tx store.Store) error {
		var e error
		summary, e = tx.AddSummary(domain.Summary{EventID: doc.EventID, RoundID: roundID, Version: doc.AnalysisVersion, Kind: doc.Kind, EventSummary: doc.Markdown})
		if e != nil {
			return fmt.Errorf("保存分析总结失败：%w", e)
		}
		if summary.ID <= 0 {
			return fmt.Errorf("report_summary_identity_missing")
		}
		doc.SummaryID = summary.ID
		if e = putRecord(ctx, tx, "report_document", reportDocumentKey(doc.EventID, summary.ID), doc.EventID, doc); e != nil {
			return fmt.Errorf("保存报告证据文档失败")
		}
		return nil
	})
	return summary, err
}

func ExportEvidenceReportDOCX(report ReportDocument) ([]byte, error) {
	doc, err := godocx.NewDocument()
	if err != nil {
		return nil, err
	}
	p := doc.AddParagraph("")
	p.Justification(stypes.JustificationCenter)
	p.AddText(report.Title).Bold(true).Size(18)
	metadata := fmt.Sprintf("报告版本 %d · 快照版本 %d · %s（北京时间）", report.AnalysisVersion, report.Evidence.SnapshotVersion, report.CreatedAt.In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01-02 15:04:05"))
	if report.SchemaVersion == "" {
		metadata = fmt.Sprintf("报告版本 %d · %s（北京时间）", report.AnalysisVersion, report.CreatedAt.In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01-02 15:04:05"))
	}
	doc.AddParagraph(metadata).AddText("").Size(9)
	lines := strings.Split(report.Markdown, "\n")
	for n := 0; n < len(lines); n++ {
		line := strings.TrimSpace(lines[n])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "|") {
			table := doc.AddTable()
			table.Style("TableGrid")
			for n < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[n]), "|") {
				text := strings.TrimSpace(lines[n])
				if !strings.Contains(text, "---") {
					row := table.AddRow()
					// Escaped pipes in actual field text are not column delimiters.
					text = strings.ReplaceAll(text, "\\|", "\x00")
					for _, cell := range strings.Split(strings.Trim(text, "|"), "|") {
						value := strings.ReplaceAll(strings.TrimSpace(cell), "\x00", "|")
						row.AddCell().AddParagraph(value)
					}
				}
				n++
			}
			n--
			continue
		}
		para := doc.AddParagraph("")
		if strings.HasPrefix(line, "## ") {
			para.Style("Heading1")
			para.AddText(strings.TrimPrefix(line, "## ")).Bold(true).Size(14)
		} else if strings.HasPrefix(line, "### ") {
			para.Style("Heading2")
			para.AddText(strings.TrimPrefix(line, "### ")).Bold(true).Size(12)
		} else {
			para.AddText(line).Size(10)
		}
	}
	// Detailed appendix comes from the SAME immutable bundle, no database
	// queries and no regeneration of historical evidence on export.
	if report.SchemaVersion != "" {
		doc.AddPageBreak()
		doc.AddParagraph("附录：正文证据来源定位").Style("Heading1")
		doc.AddParagraph(fmt.Sprintf("事件：%s；快照版本：%d；命中水位：%d；修订水位：%d。", report.EventID, report.Evidence.SnapshotVersion, report.Evidence.Watermark, report.Evidence.RevisionWatermark))
		selected := map[string]bool{}
		for _, id := range report.Evidence.SelectedIDs {
			selected[id] = true
		}
		for _, e := range report.Evidence.Entries {
			if !selected[e.ID] {
				continue
			}
			doc.AddParagraph(e.ID + " · " + e.Name).AddText("").Bold(true)
			doc.AddParagraph("来源：" + e.Source)
			if e.Scope.AssetID != "" || e.Scope.EndpointID != "" {
				doc.AddParagraph("核验范围：资产=" + e.Scope.AssetID + "；端点=" + e.Scope.EndpointID + "；设备=" + e.Scope.DeviceID + "；群体=" + e.Scope.GroupID)
			}
			if e.Window != nil {
				doc.AddParagraph("核验窗口（UTC）：" + e.Window.Start.UTC().Format(time.RFC3339Nano) + " 至 " + e.Window.End.UTC().Format(time.RFC3339Nano) + "；边界约定=" + e.Window.Convention)
			}
			if len(e.SourceIDs) > 0 {
				doc.AddParagraph(fmt.Sprintf("来源标识共%d条；以下展示前%d条定位入口：%s", len(e.SourceIDs), min(8, len(e.SourceIDs)), strings.Join(e.SourceIDs[:min(8, len(e.SourceIDs))], "；")))
			}
		}
		doc.AddParagraph("附录：完整事实检查清单").Style("Heading1")
		table := doc.AddTable()
		table.Style("TableGrid")
		header := table.AddRow()
		for _, v := range []string{"事实规则", "范围", "核验状态", "结果或缺项原因"} {
			header.AddCell().AddParagraph(v)
		}
		for _, f := range report.Evidence.FactChecks {
			row := table.AddRow()
			for _, v := range []string{string(f.FactID), f.Scope.AssetID + " / " + f.Scope.EndpointID, string(f.Status), string(f.ReasonCode) + "；" + reportFactMeasurements(f)} {
				row.AddCell().AddParagraph(v)
			}
		}
		if len(report.Evidence.FactChecks) == 0 {
			for _, f := range report.Evidence.FactCoverage {
				row := table.AddRow()
				for _, v := range []string{string(f.FactID), f.Scope.AssetID + " / " + f.Scope.EndpointID, f.Status, string(f.Reason)} {
					row.AddCell().AddParagraph(v)
				}
			}
		}
		doc.AddParagraph("语义任务检查清单").Style("Heading1")
		table = doc.AddTable()
		table.Style("TableGrid")
		header = table.AddRow()
		for _, v := range []string{"槽位", "命题", "执行状态", "原因"} {
			header.AddCell().AddParagraph(v)
		}
		for _, x := range report.Evidence.SemanticChecks {
			row := table.AddRow()
			for _, v := range []string{x.Slot.String(), x.SubjectID, x.Status, x.Reason} {
				row.AddCell().AddParagraph(v)
			}
		}
	}
	var out bytes.Buffer
	if err = doc.Write(&out); err != nil {
		return nil, err
	}
	return styleEvidenceDOCX(out.Bytes())
}

// godocx 0.1.5 lacks row/header and paragraph pagination setters. Apply those
// presentation properties to its generated OOXML without reflection/unsafe.
func styleEvidenceDOCX(raw []byte) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, file := range reader.File {
		r, e := file.Open()
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(r)
		r.Close()
		if e != nil {
			return nil, e
		}
		if file.Name == "word/document.xml" {
			xml := string(data)
			section := `<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="850" w:bottom="1134" w:left="850" w:header="425" w:footer="425"/></w:sectPr>`
			re := regexp.MustCompile(`(?s)<w:sectPr[^>]*>.*?</w:sectPr>`)
			if re.MatchString(xml) {
				xml = re.ReplaceAllString(xml, section)
			} else {
				xml = strings.Replace(xml, "</w:body>", section+"</w:body>", 1)
			}
			// Chinese and western fonts, line height, and paragraph spacing.
			xml = strings.ReplaceAll(xml, "<w:rPr>", `<w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="微软雅黑"/>`)
			xml = regexp.MustCompile(`<w:spacing\b[^>]*/>`).ReplaceAllString(xml, "")
			xml = strings.ReplaceAll(xml, "<w:pPr>", `<w:pPr><w:spacing w:after="100" w:line="300" w:lineRule="auto"/>`)
			xml = strings.ReplaceAll(xml, "<w:trPr>", `<w:trPr><w:cantSplit/>`)
			// Repeat the first row of every table and shade its cells.
			tables := regexp.MustCompile(`(?s)<w:tbl>.*?</w:tbl>`)
			rows := regexp.MustCompile(`(?s)<w:tr>.*?</w:tr>`)
			xml = tables.ReplaceAllStringFunc(xml, func(table string) string {
				loc := rows.FindStringIndex(table)
				if loc == nil {
					return table
				}
				row := table[loc[0]:loc[1]]
				row = strings.Replace(row, "<w:trPr>", "<w:trPr><w:tblHeader/>", 1)
				cells := regexp.MustCompile(`(?s)<w:tc>.*?</w:tc>`)
				row = cells.ReplaceAllStringFunc(row, func(cell string) string {
					if strings.Contains(cell, "<w:tcPr>") {
						return strings.Replace(cell, "<w:tcPr>", `<w:tcPr><w:shd w:fill="E8EEF6"/>`, 1)
					}
					if strings.Contains(cell, "<w:tcPr/>") {
						return strings.Replace(cell, "<w:tcPr/>", `<w:tcPr><w:shd w:fill="E8EEF6"/></w:tcPr>`, 1)
					}
					return strings.Replace(cell, "<w:tc>", `<w:tc><w:tcPr><w:shd w:fill="E8EEF6"/></w:tcPr>`, 1)
				})
				return table[:loc[0]] + row + table[loc[1]:]
			})
			data = []byte(xml)
		}
		w, e := writer.Create(file.Name)
		if e != nil {
			return nil, e
		}
		if _, e = w.Write(data); e != nil {
			return nil, e
		}
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
