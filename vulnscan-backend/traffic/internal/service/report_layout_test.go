package service

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestFivePartReportLayoutAndPinnedExport(t *testing.T) {
	svc, event, b := reportTestBundle(t)
	a := validReportAssessment(b)
	a.Risks = []ReportRisk{{EvidenceIDs: []string{b.SelectedIDs[0]}, Exposure: "通信归属", Impact: "若通联被滥用，可能影响资产业务"}}
	if err := validateReportAssessment(a, b); err != nil {
		t.Fatal(err)
	}
	doc := ReportDocument{SchemaVersion: reportEvidenceVersion, LayoutVersion: reportFivePartLayout, EventID: event.EventID, Title: "研判报告", CreatedAt: time.Now(), AnalysisVersion: 1, Kind: AnalysisKindInitial, Evidence: b, Assessment: a, Validation: "references_and_facts_validated"}
	doc.Evidence.Overview.First = time.Date(2026, 10, 13, 6, 53, 0, 0, time.UTC)
	doc.Evidence.Overview.Last = time.Date(2026, 10, 13, 6, 56, 0, 0, time.UTC)
	doc.EventOverview = reportEventOverview(event, `{"first_time":"2026-10-13T06:53:00Z","last_time":"2026-10-13T06:56:00Z","src_ip":"180.104.100.118","dst_ip":"172.67.190.89","dst_port":443,"protocol":"TCP","occurrence_count":6}`, "业务归属未确认")
	doc.Markdown = renderReportMarkdown(doc)
	previous := -1
	for _, title := range []string{"## 一、研判结论", "## 二、事件概览", "## 三、关键证据", "## 四、风险分析", "## 五、处置建议"} {
		pos := strings.Index(doc.Markdown, title)
		if pos <= previous {
			t.Fatalf("missing or unordered heading: %s", title)
		}
		previous = pos
	}
	if strings.Count(doc.Markdown, "## ") != 5 || strings.Contains(doc.Markdown, "模型估计") || strings.Contains(doc.Markdown, "附录") || !strings.Contains(doc.Markdown, "14:53:00") {
		t.Fatal(doc.Markdown)
	}
	summary, err := svc.saveReportDocument(context.Background(), doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := svc.ReportDocument(context.Background(), event.EventID, summary.ID)
	if err != nil || pinned.LayoutVersion != reportFivePartLayout {
		t.Fatalf("pinned read: %v", err)
	}
	raw, err := ExportEvidenceReportDOCX(pinned)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range archive.File {
		if file.Name == "word/document.xml" {
			r, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			xml, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(xml), "附录：") || !strings.Contains(string(xml), "二、事件概览") {
				t.Fatal("incorrect DOCX sections")
			}
		}
	}
	a.Risks[0].EvidenceIDs = []string{"E-unknown"}
	if validateReportAssessment(a, b) == nil {
		t.Fatal("unbound risk accepted")
	}
}
