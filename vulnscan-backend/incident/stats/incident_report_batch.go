package stats

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"time"

	"vulnscan-backend/model"
)

func (s *serviceStats) exportBatchReportsZip(ctx context.Context, incidents []model.SecurityIncident, format string) ([]byte, string, error) {
	if len(incidents) == 0 {
		return nil, "", fmt.Errorf("没有可导出的事件")
	}
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	added := 0
	for i := range incidents {
		incident, logs, vulns, err := s.loadIncidentReportBundle(ctx, incidents[i].Id)
		if err != nil {
			continue
		}
		data := buildIncidentReportData(*incident, logs, vulns)
		s.enrichReportEvidence(ctx, data)
		raw, filename, err := generateIncidentReport(data, format)
		if err != nil {
			return nil, "", err
		}
		w, err := zw.Create(filename)
		if err != nil {
			return nil, "", err
		}
		if _, err := w.Write(raw); err != nil {
			return nil, "", err
		}
		added++
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	if added == 0 {
		return nil, "", fmt.Errorf("没有成功生成任何报告")
	}
	name := fmt.Sprintf("incidents_%s_%s.zip", format, time.Now().Format("20060102150405"))
	return buf.Bytes(), name, nil
}
