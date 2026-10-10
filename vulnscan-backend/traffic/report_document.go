package traffic

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/gin-gonic/gin"
	trafficservice "vulnscan-backend/traffic/internal/service"
)

func (s *EventService) ReportDocument(ctx context.Context, eventID string, summaryID int64) (trafficservice.ReportDocument, error) {
	return s.core.ReportDocument(ctx, eventID, summaryID)
}

func reportSummaryID(c *gin.Context) (int64, error) {
	raw := c.Query("summary_id")
	if raw == "" {
		return 0, nil
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("summary_id必须为正整数")
	}
	return id, nil
}
func (h *Handler) EventReportDocument(c *gin.Context) {
	id, err := reportSummaryID(c)
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	doc, err := h.events.ReportDocument(c.Request.Context(), c.Param("eventID"), id)
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	ok(c, doc)
}
func (h *Handler) ExportEventReport(c *gin.Context) {
	id, err := reportSummaryID(c)
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	doc, err := h.events.ReportDocument(c.Request.Context(), c.Param("eventID"), id)
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	data, err := trafficservice.ExportEvidenceReportDOCX(doc)
	if err != nil {
		fail(c, 500, "报告导出失败")
		return
	}
	c.Header("Content-Disposition", `attachment; filename="evidence-report.docx"; filename*=UTF-8''`+url.PathEscape(doc.Title+".docx"))
	c.Data(200, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", data)
}
