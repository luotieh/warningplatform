package stats

import (
	"fmt"
	"net/http"

	statsContract "vulnscan-backend/incident/stats/stats-contract"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type HandlerStats struct {
	svc statsContract.ServiceStats
}

func NewHandlerStats(svc statsContract.ServiceStats) *HandlerStats {
	return &HandlerStats{svc: svc}
}

func (h *HandlerStats) RemediationStats(c *gin.Context) {
	stats, err := h.svc.GetRemediationStats(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(stats).Send()
}

func (h *HandlerStats) OverdueList(c *gin.Context) {
	req, ok := web.BindQuery[statsContract.OverdueListReq](c)
	if !ok {
		return
	}
	items, count, err := h.svc.GetOverdueList(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerStats) MultiDimAnalysis(c *gin.Context) {
	query, ok := web.BindQuery[struct {
		Dimension string `form:"dimension"`
	}](c)
	if !ok {
		return
	}
	dimension := query.Dimension
	if dimension == "" {
		dimension = "level"
	}
	items, err := h.svc.GetMultiDimAnalysis(c.Request.Context(), dimension)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(items).Send()
}

func (h *HandlerStats) GenerateReport(c *gin.Context) {
	req, ok := web.BindQuery[statsContract.ReportReq](c)
	if !ok {
		return
	}
	data, filename, err := h.svc.GenerateReport(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Data(http.StatusOK, "text/csv; charset=utf-8", data)
}

func (h *HandlerStats) ExportBatch(c *gin.Context) {
	req, ok := web.BindJSON[struct {
		IDs    []string `json:"ids" binding:"required"`
		Format string   `json:"format"`
	}](c)
	if !ok {
		return
	}
	format := req.Format
	if format == "" {
		format = "csv"
	}
	data, filename, err := h.svc.ExportBatch(c.Request.Context(), req.IDs, format)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Data(http.StatusOK, "text/csv; charset=utf-8", data)
}

func (h *HandlerStats) ExportSingle(c *gin.Context) {
	req, ok := web.BindQuery[struct {
		ID     string `form:"id" binding:"required"`
		Format string `form:"format"`
	}](c)
	if !ok {
		return
	}
	format := req.Format
	if format == "" {
		format = "csv"
	}
	data, filename, err := h.svc.ExportSingle(c.Request.Context(), req.ID, format)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Data(http.StatusOK, "text/csv; charset=utf-8", data)
}

func (h *HandlerStats) TrendPrediction(c *gin.Context) {
	req, ok := web.BindQuery[struct {
		RangeType   string `form:"range_type"`
		PredictDays int    `form:"predict_days"`
	}](c)
	if !ok {
		return
	}
	if req.RangeType == "" {
		req.RangeType = "30d"
	}
	if req.PredictDays <= 0 {
		req.PredictDays = 7
	}
	result, err := h.svc.GetTrendPrediction(c.Request.Context(), req.RangeType, req.PredictDays)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(result).Send()
}

func (h *HandlerStats) AIAnalysis(c *gin.Context) {
	result, err := h.svc.GetAIAnalysis(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(result).Send()
}

func (h *HandlerStats) AssetProfile(c *gin.Context) {
	req, ok := web.BindQuery[statsContract.AssetProfileReq](c)
	if !ok {
		return
	}
	result, err := h.svc.GetAssetProfile(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(result).Send()
}

func (h *HandlerStats) AssetSummary(c *gin.Context) {
	req, ok := web.BindQuery[statsContract.AssetListReq](c)
	if !ok {
		return
	}
	items, count, err := h.svc.ListAssetSummary(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}
