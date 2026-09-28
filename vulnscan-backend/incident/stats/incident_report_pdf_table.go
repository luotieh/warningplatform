package stats

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	statsContract "vulnscan-backend/incident/stats/stats-contract"

	"github.com/go-pdf/fpdf"
)

// pdfReportTable 手绘表格，长文本按页分段并保留完整边框（避免 MultiCell 跨页缺线）。
type pdfReportTable struct {
	pdf        *fpdf.Fpdf
	x0         float64
	labelW     float64
	contentW   float64
	pageBottom float64
}

func newPDFReportTable(pdf *fpdf.Fpdf, labelW float64) *pdfReportTable {
	l, _, r, _ := pdf.GetMargins()
	pageW, pageH := pdf.GetPageSize()
	_, _, _, bottom := pdf.GetMargins()
	t := &pdfReportTable{
		pdf:        pdf,
		x0:         l,
		labelW:     labelW,
		contentW:   pageW - l - r - labelW,
		pageBottom: pageH - bottom,
	}
	return t
}

func (t *pdfReportTable) totalW() float64 {
	return t.labelW + t.contentW
}

func (t *pdfReportTable) wrapText(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	var lines []string
	for _, para := range strings.Split(text, "\n") {
		if strings.TrimSpace(para) == "" {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, t.pdf.SplitText(para, t.contentW-4)...)
	}
	if len(lines) == 0 {
		return nil
	}
	return lines
}

func (t *pdfReportTable) linesFit(lineH float64, n int) int {
	y := t.pdf.GetY()
	avail := t.pageBottom - y
	if avail < lineH*2 {
		return 0
	}
	max := int(avail / lineH)
	if max < 1 {
		return 0
	}
	if n > max {
		return max
	}
	return n
}

func (t *pdfReportTable) newPage() {
	t.pdf.AddPage()
	t.pdf.SetFont("report-font", "", 9.5)
}

func (t *pdfReportTable) drawSegmentBorder(y, h float64) {
	x := t.x0
	w := t.totalW()
	t.pdf.Rect(x, y, w, h, "D")
	t.pdf.Line(x+t.labelW, y, x+t.labelW, y+h)
}

func (t *pdfReportTable) drawLabelAt(y float64, label string, h, pad, lineH float64) {
	if strings.TrimSpace(label) == "" {
		return
	}
	t.pdf.SetXY(t.x0+pad, y+pad)
	t.pdf.MultiCell(t.labelW-pad*2, lineH, label, "", "L", false)
	_ = h
}

func (t *pdfReportTable) drawContentLines(y float64, lines []string, lineH, pad float64) {
	contentX := t.x0 + t.labelW + pad
	t.pdf.SetXY(contentX, y+pad)
	for _, line := range lines {
		t.pdf.SetX(contentX)
		t.pdf.CellFormat(t.contentW-pad*2, lineH, line, "", 1, "L", false, 0, "")
	}
}

func (t *pdfReportTable) drawLabeledBlock(label, text string, lineH float64) {
	lines := t.wrapText(text)
	if len(lines) == 0 && strings.TrimSpace(text) != "" {
		lines = []string{text}
	}
	if len(lines) == 0 {
		return
	}

	idx := 0
	first := true
	for idx < len(lines) {
		fit := t.linesFit(lineH, len(lines)-idx)
		if fit == 0 {
			t.newPage()
			continue
		}
		chunk := lines[idx : idx+fit]
		idx += fit

		segLabel := label
		if !first {
			segLabel = "（续）"
		}
		first = false

		pad := 2.0
		chunkH := float64(len(chunk))*lineH + pad*2
		labelLines := 1
		if strings.TrimSpace(segLabel) != "" {
			labelLines = len(t.pdf.SplitText(segLabel, t.labelW-4))
			if labelLines < 1 {
				labelLines = 1
			}
		}
		labelH := float64(labelLines)*lineH + pad*2
		segH := chunkH
		if labelH > segH {
			segH = labelH
		}

		segY := t.pdf.GetY()
		t.drawSegmentBorder(segY, segH)
		t.drawLabelAt(segY, segLabel, segH, pad, lineH)
		t.drawContentLines(segY, chunk, lineH, pad)
		t.pdf.SetXY(t.x0, segY+segH)
	}
}

func (t *pdfReportTable) drawShortRow2Col(label, value string, rowH float64) {
	if strings.TrimSpace(value) == "" {
		value = "-"
	}
	t.pdf.SetFont("report-font", "", 10)
	wrapped := t.pdf.SplitText(value, t.contentW-4)
	lineH := 5.0
	needH := rowH
	if len(wrapped) > 1 {
		needH = float64(len(wrapped))*lineH + 4
	}
	if t.pageBottom-t.pdf.GetY() < needH+1 {
		t.newPage()
	}
	y := t.pdf.GetY()
	t.drawSegmentBorder(y, needH)
	t.pdf.SetXY(t.x0+2, y+2)
	t.pdf.CellFormat(t.labelW-4, needH-4, label, "", 0, "L", false, 0, "")
	if len(wrapped) <= 1 {
		t.pdf.SetXY(t.x0+t.labelW+2, y+2)
		t.pdf.CellFormat(t.contentW-4, needH-4, value, "", 0, "L", false, 0, "")
	} else {
		t.drawContentLines(y, wrapped, lineH, 2)
	}
	t.pdf.SetXY(t.x0, y+needH)
}

// drawShortRow4Col 绘制 4 列行（标签/值/标签/值），两个值列等宽，
// 长文本按值列宽度自动换行，行高取两列中较多的行数。
func (t *pdfReportTable) drawShortRow4Col(k1, v1, k2, v2 string, rowH float64) {
	t.pdf.SetFont("report-font", "", 10)
	valW := (t.totalW() - 2*t.labelW) / 2
	lineH := 5.0
	w1 := t.pdf.SplitText(dashIfEmpty(v1), valW-4)
	w2 := t.pdf.SplitText(dashIfEmpty(v2), valW-4)
	n := len(w1)
	if len(w2) > n {
		n = len(w2)
	}
	if n < 1 {
		n = 1
	}
	needH := rowH
	if n > 1 {
		needH = float64(n)*lineH + 4
	}
	if t.pageBottom-t.pdf.GetY() < needH+1 {
		t.newPage()
	}
	x := t.x0
	y := t.pdf.GetY()
	t.pdf.Rect(x, y, t.totalW(), needH, "D")
	t.pdf.Line(x+t.labelW, y, x+t.labelW, y+needH)
	t.pdf.Line(x+t.labelW+valW, y, x+t.labelW+valW, y+needH)
	t.pdf.Line(x+2*t.labelW+valW, y, x+2*t.labelW+valW, y+needH)
	t.pdf.SetXY(x+2, y+2)
	t.pdf.CellFormat(t.labelW-4, needH-4, k1, "", 0, "L", false, 0, "")
	t.pdf.SetXY(x+t.labelW+valW+2, y+2)
	t.pdf.CellFormat(t.labelW-4, needH-4, k2, "", 0, "L", false, 0, "")
	t.drawColumnText(x+t.labelW, y, valW, w1, lineH, 2)
	t.drawColumnText(x+2*t.labelW+valW, y, valW, w2, lineH, 2)
	t.pdf.SetXY(x, y+needH)
}

// drawColumnText 在指定列区域按行绘制文本。
func (t *pdfReportTable) drawColumnText(x, y, w float64, lines []string, lineH, pad float64) {
	if len(lines) == 0 {
		lines = []string{"-"}
	}
	t.pdf.SetXY(x+pad, y+pad)
	for _, line := range lines {
		t.pdf.SetX(x + pad)
		t.pdf.CellFormat(w-pad*2, lineH, line, "", 1, "L", false, 0, "")
	}
}

func (t *pdfReportTable) drawMetaRows(data *statsContract.IncidentReportData) {
	t.pdf.SetFont("report-font", "", 10)
	for _, row := range incidentReportMetaRows(data) {
		if row[2] != "" {
			t.drawShortRow4Col(row[0], row[1], row[2], row[3], 7)
		} else {
			t.drawShortRow2Col(row[0], row[1], 7)
		}
	}
}

func (t *pdfReportTable) drawDescription(data *statsContract.IncidentReportData, lineH float64) {
	text := formatDescriptionForReport(data)
	hasImages := false
	for _, img := range data.EvidenceImages {
		if strings.TrimSpace(img.Base64) != "" {
			hasImages = true
			break
		}
	}
	if text == "" && !hasImages {
		return
	}
	if text == "" {
		text = "（无文字描述，见下方图像证据）"
	}
	t.pdf.SetFont("report-font", "", 9.5)
	t.drawLabeledBlock("隐患描述", text, lineH)

	for i, img := range data.EvidenceImages {
		if strings.TrimSpace(img.Base64) == "" {
			continue
		}
		t.drawEvidenceImage(i, img, lineH)
	}
}

func (t *pdfReportTable) drawRemediation(data *statsContract.IncidentReportData, lineH float64) {
	if !hasAny(data.RemediationPlan, data.RemediationAdvice) {
		return
	}
	var b strings.Builder
	if strings.TrimSpace(data.RemediationPlan) != "" {
		b.WriteString(data.RemediationPlan)
	}
	if strings.TrimSpace(data.RemediationAdvice) != "" &&
		data.RemediationAdvice != data.RemediationPlan {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(data.RemediationAdvice)
	}
	t.pdf.SetFont("report-font", "", 9.5)
	t.drawLabeledBlock("整改建议", b.String(), lineH)
}

// drawAnalysis 渲染安全事件分析扩展章节（事件概述/流量证据与IOC/影响评估/处置/附件）。
func (t *pdfReportTable) drawAnalysis(data *statsContract.IncidentReportData, lineH float64) {
	blocks := reportAnalysisBlocks(data)
	if len(blocks) == 0 {
		return
	}
	t.pdf.SetFont("report-font", "", 9.5)
	for _, block := range blocks {
		t.drawLabeledBlock(block.Title, block.Body, lineH)
	}
}

func (t *pdfReportTable) drawEvidenceImage(idx int, img statsContract.IncidentReportEvidenceImage, lineH float64) {
	raw, err := base64.StdEncoding.DecodeString(img.Base64)
	if err != nil || len(raw) == 0 {
		return
	}
	name := fmt.Sprintf("evidence_%d", idx)
	opt := fpdf.ImageOptions{ImageType: "PNG", ReadDpi: true}
	_ = t.pdf.RegisterImageOptionsReader(name, opt, bytes.NewReader(raw))
	if t.pdf.Err() {
		t.pdf.SetError(nil)
		return
	}

	caption := img.Caption
	if strings.TrimSpace(caption) == "" {
		caption = "监测截图证据"
	}

	imgW := t.contentW - 16
	if imgW > 160 {
		imgW = 160
	}
	imgH := 55.0
	needH := lineH + 4 + imgH + 8

	if t.pageBottom-t.pdf.GetY() < needH {
		t.newPage()
	}

	pad := 2.0
	segY := t.pdf.GetY()
	segH := needH
	t.drawSegmentBorder(segY, segH)

	t.pdf.SetXY(t.x0+t.labelW+pad, segY+pad)
	t.pdf.CellFormat(t.contentW-pad*2, lineH, caption, "", 1, "C", false, 0, "")
	imgY := t.pdf.GetY() + 2
	t.pdf.ImageOptions(name, t.x0+t.labelW+8, imgY, imgW, 0, false, opt, 0, "")
	t.pdf.SetXY(t.x0, segY+segH)
}
