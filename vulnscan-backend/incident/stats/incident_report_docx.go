package stats

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"

	statsContract "vulnscan-backend/incident/stats/stats-contract"

	"github.com/gomutex/godocx"
	"github.com/gomutex/godocx/common/units"
	godocxdocx "github.com/gomutex/godocx/docx"
	"github.com/gomutex/godocx/wml/stypes"
)

func generateIncidentDocx(data *statsContract.IncidentReportData) ([]byte, error) {
	doc, err := godocx.NewDocument()
	if err != nil {
		return nil, err
	}

	title := doc.AddParagraph("")
	title.Justification(stypes.JustificationCenter)
	title.AddText("网络安全隐患详情").Bold(true).Size(32)

	// 两列表格：左标签、右内容，避免四列过窄导致竖排
	tbl := doc.AddTable()
	tbl.Style("TableGrid")

	for _, row := range incidentReportMetaRows(data) {
		docxAddMetaRow2Col(tbl, row[0], row[1], row[2], row[3])
	}
	docxAddDescriptionRow2Col(tbl, data)
	docxAddRemediationRow2Col(tbl, data)
	if strings.TrimSpace(data.Attachment) != "" {
		docxAddMetaRow2Col(tbl, "证据附件", data.Attachment, "", "")
	}

	var buf bytes.Buffer
	if err := doc.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func docxAddMetaRow2Col(tbl *godocxdocx.Table, k1, v1, k2, v2 string) {
	if strings.TrimSpace(k2) != "" {
		docxAddLabelValueRow(tbl, k1, v1)
		docxAddLabelValueRow(tbl, k2, v2)
		return
	}
	docxAddLabelValueRow(tbl, k1, v1)
}

func docxAddLabelValueRow(tbl *godocxdocx.Table, label, value string) {
	tr := tbl.AddRow()
	docxLabelCell(tr.AddCell(), label)
	docxValueCell(tr.AddCell(), value)
}

func docxLabelCell(cell *godocxdocx.Cell, text string) {
	if strings.TrimSpace(text) == "" {
		cell.AddEmptyPara()
		return
	}
	p := cell.AddParagraph("")
	p.AddText(text).Bold(true)
}

func docxValueCell(cell *godocxdocx.Cell, text string) {
	if strings.TrimSpace(text) == "" {
		cell.AddEmptyPara()
		return
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		if i == 0 && line != "" {
			cell.AddParagraph(line)
		} else if line == "" {
			cell.AddEmptyPara()
		} else {
			cell.AddParagraph(line)
		}
	}
}

func docxAddDescriptionRow2Col(tbl *godocxdocx.Table, data *statsContract.IncidentReportData) {
	blocks := reportDescriptionBlocks(data)
	if len(blocks) == 0 && len(data.EvidenceImages) == 0 {
		return
	}
	tr := tbl.AddRow()
	docxLabelCell(tr.AddCell(), "隐患描述")
	valCell := tr.AddCell()

	for _, block := range blocks {
		sec := valCell.AddParagraph("")
		sec.AddText(block.Title).Bold(true)
		for _, line := range strings.Split(block.Body, "\n") {
			line = strings.TrimRight(line, "\r")
			if line == "" {
				valCell.AddEmptyPara()
				continue
			}
			valCell.AddParagraph(line)
		}
		valCell.AddEmptyPara()
	}
	for _, img := range data.EvidenceImages {
		if strings.TrimSpace(img.Base64) == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(img.Base64)
		if err != nil || len(raw) == 0 {
			continue
		}
		if strings.TrimSpace(img.Caption) != "" {
			cap := valCell.AddParagraph(img.Caption)
			cap.Justification(stypes.JustificationCenter)
		}
		p := valCell.AddEmptyPara()
		docxAddPictureFromBytes(p, raw)
		valCell.AddEmptyPara()
	}
}

func docxAddPictureFromBytes(p *godocxdocx.Paragraph, raw []byte) {
	f, err := os.CreateTemp("", "incident-evidence-*.png")
	if err != nil {
		return
	}
	path := f.Name()
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return
	}
	_ = f.Close()
	defer os.Remove(path)
	_, _ = p.AddPicture(path, units.Inch(5.5), units.Inch(3.1))
}

func docxAddRemediationRow2Col(tbl *godocxdocx.Table, data *statsContract.IncidentReportData) {
	if !hasAny(data.RemediationPlan, data.RemediationAdvice) {
		return
	}
	tr := tbl.AddRow()
	docxLabelCell(tr.AddCell(), "整改建议")
	valCell := tr.AddCell()
	if strings.TrimSpace(data.RemediationPlan) != "" {
		for _, line := range strings.Split(data.RemediationPlan, "\n") {
			if strings.TrimSpace(line) != "" {
				valCell.AddParagraph(line)
			}
		}
	}
	if strings.TrimSpace(data.RemediationAdvice) != "" &&
		data.RemediationAdvice != data.RemediationPlan {
		for _, line := range strings.Split(data.RemediationAdvice, "\n") {
			if strings.TrimSpace(line) != "" {
				valCell.AddParagraph(line)
			}
		}
	}
}
