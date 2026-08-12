package stats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	statsContract "vulnscan-backend/incident/stats/stats-contract"

	"github.com/go-pdf/fpdf"
)

func generateIncidentReport(data *statsContract.IncidentReportData, format string) ([]byte, string, error) {
	switch format {
	case "json":
		raw, err := json.MarshalIndent(data, "", "  ")
		return raw, fmt.Sprintf("incident_%s.json", data.IncidentNo), err
	case "word", "docx":
		raw, err := generateIncidentDocx(data)
		return raw, fmt.Sprintf("incident_%s.docx", data.IncidentNo), err
	case "pdf":
		raw, err := generateIncidentPDF(data)
		return raw, fmt.Sprintf("incident_%s.pdf", data.IncidentNo), err
	default:
		return nil, "", fmt.Errorf("不支持的格式: %s", format)
	}
}

func generateIncidentPDF(data *statsContract.IncidentReportData) ([]byte, error) {
	fontBytes, err := loadIncidentPDFFont()
	if err != nil {
		return nil, err
	}
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(14, 14, 14)
	pdf.SetAutoPageBreak(true, 14)
	pdf.AddUTF8FontFromBytes("report-font", "", fontBytes)
	pdf.SetFont("report-font", "", 10)
	pdf.AddPage()

	pdf.SetFont("report-font", "", 15)
	pdf.CellFormat(0, 9, "网络安全隐患详情", "", 1, "C", false, 0, "")
	pdf.Ln(3)
	pdf.SetFont("report-font", "", 10)

	tbl := newPDFReportTable(pdf, 34)
	tbl.drawMetaRows(data)
	tbl.drawDescription(data, 4.8)
	tbl.drawRemediation(data, 4.8)
	tbl.drawAnalysis(data, 4.8)
	if strings.TrimSpace(data.Attachment) != "" {
		tbl.drawShortRow2Col("证据附件", data.Attachment, 7)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func formatDescriptionForReport(data *statsContract.IncidentReportData) string {
	var b strings.Builder
	for _, block := range reportDescriptionBlocks(data) {
		b.WriteString(block.Title + "\n")
		b.WriteString(block.Body + "\n\n")
	}
	return strings.TrimSpace(b.String())
}

func loadIncidentPDFFont() ([]byte, error) {
	candidates := []string{
		filepath.Join(os.Getenv("WINDIR"), "Fonts", "simhei.ttf"),
		filepath.Join(os.Getenv("WINDIR"), "Fonts", "Deng.ttf"),
		filepath.Join(os.Getenv("WINDIR"), "Fonts", "simsunb.ttf"),
		"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/opentype/noto/NotoSansCJKSC-Regular.otf",
		"/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
	}
	for _, path := range candidates {
		if strings.TrimSpace(path) == "" {
			continue
		}
		content, err := os.ReadFile(path)
		if err == nil {
			return content, nil
		}
	}
	return nil, fmt.Errorf("生成 PDF 失败：未找到可用的中文字体")
}
