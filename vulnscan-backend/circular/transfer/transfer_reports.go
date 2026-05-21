package transfer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	transferContract "vulnscan-backend/circular/transfer/transfer-contract"
	"vulnscan-backend/model"
)

const circularReportDir = "data/circular-reports"

func (s *serviceTransfer) SetIncidentReportExporter(exporter transferContract.IncidentReportExporter) {
	s.reporter = exporter
}

func (s *serviceTransfer) ExportCircularIncidentReport(ctx context.Context, circularID, format string) ([]byte, string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "pdf"
	}
	if format != "pdf" && format != "docx" && format != "word" {
		return nil, "", fmt.Errorf("不支持的报告格式: %s", format)
	}
	if format == "word" {
		format = "docx"
	}

	sess := s.session()
	var record model.CircularTransferRecord
	if err := sess.WithContext(ctx).Where("circular_id = ?", circularID).First(&record).Error; err != nil {
		return nil, "", fmt.Errorf("未找到流转记录")
	}
	if strings.TrimSpace(record.IncidentID) == "" {
		return nil, "", fmt.Errorf("该通报未关联安全事件，无法导出报告")
	}

	if raw, name, err := readCircularReportFile(circularID, format); err == nil && len(raw) > 0 {
		return raw, name, nil
	}
	if s.reporter == nil {
		return nil, "", fmt.Errorf("报告生成服务未就绪")
	}
	return s.reporter.ExportIncidentReport(ctx, record.IncidentID, format)
}

func (s *serviceTransfer) attachIncidentReports(
	ctx context.Context,
	circularCode string,
	req transferContract.TransferIncidentReq,
	data model.JSONMapSlice,
) model.JSONMapSlice {
	incidentID := strings.TrimSpace(req.IncidentID)
	if incidentID == "" {
		return data
	}
	data = append(data, map[string]any{
		"title": "关联安全事件", "type": "input", "value": req.IncidentNo,
	})
	if s.reporter == nil {
		data = append(data, map[string]any{
			"title": "隐患报告说明", "type": "input",
			"value": "报告生成服务未就绪，请从安全事件详情导出 Word/PDF",
		})
		return data
	}

	for _, format := range []string{"docx", "pdf"} {
		raw, filename, err := s.reporter.ExportIncidentReport(ctx, incidentID, format)
		if err != nil || len(raw) == 0 {
			continue
		}
		if err := writeCircularReportFile(circularCode, format, raw); err != nil {
			continue
		}
		label := "隐患报告(Word)"
		if format == "pdf" {
			label = "隐患报告(PDF)"
		}
		data = append(data, map[string]any{
			"title":        label,
			"type":         "link",
			"value":        filename,
			"download_url": circularReportAPIPath(circularCode, format),
		})
	}
	return data
}

func circularReportAPIPath(circularCode, format string) string {
	return fmt.Sprintf("/circular/transfers/reports/%s/%s", circularCode, format)
}

func circularReportFilePath(circularCode, format string) string {
	name := "incident_report.pdf"
	if format == "docx" {
		name = "incident_report.docx"
	}
	return filepath.Join(circularReportDir, circularCode, name)
}

func writeCircularReportFile(circularCode, format string, raw []byte) error {
	path := circularReportFilePath(circularCode, format)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func readCircularReportFile(circularCode, format string) ([]byte, string, error) {
	path := circularReportFilePath(circularCode, format)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	return raw, filepath.Base(path), nil
}
