package stats

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	statsContract "vulnscan-backend/incident/stats/stats-contract"
)

// reportObjectStore 读取站点监测对象存储中的证据文件（可选依赖）。
type reportObjectStore interface {
	ObjGetRaw(ctx context.Context, key string) ([]byte, error)
}

func (s *serviceStats) enrichReportEvidence(ctx context.Context, data *statsContract.IncidentReportData) {
	if data == nil || s.objStore == nil {
		return
	}
	execID := extractMonitorExecutionID(data.Description)
	if execID == "" {
		execID = extractMonitorExecutionID(data.DescriptionSections.Trace)
	}
	if execID == "" {
		return
	}

	candidates := []struct {
		asset   string
		caption string
		mime    string
	}{
		{"screenshot", "监测截图证据", "image/png"},
	}
	for _, c := range candidates {
		key := fmt.Sprintf("evidence/%s/%s", execID, c.asset)
		raw, err := s.objStore.ObjGetRaw(ctx, key)
		if err != nil || len(raw) == 0 {
			continue
		}
		data.EvidenceImages = append(data.EvidenceImages, statsContract.IncidentReportEvidenceImage{
			Caption:  c.caption,
			MIMEType: c.mime,
			Base64:   base64.StdEncoding.EncodeToString(raw),
		})
	}
	if len(data.EvidenceImages) > 0 {
		names := make([]string, 0, len(data.EvidenceImages))
		for _, img := range data.EvidenceImages {
			names = append(names, img.Caption)
		}
		data.Attachment = strings.Join(names, "；")
	}
}
