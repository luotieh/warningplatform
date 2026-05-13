package sitemonitor

import (
	"strconv"
	"time"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

// ══ Dashboard ══

func (h *HandlerMonitor) GetTaskTrend(c *gin.Context) {
	taskID := c.Param("id")
	hoursStr := c.DefaultQuery("hours", "24")
	hours := 24
	if v, err := strconv.Atoi(hoursStr); err == nil && v > 0 && v <= 720 {
		hours = v
	}
	resp, err := h.svc.GetTaskTrend(c.Request.Context(), taskID, hours)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(resp).Send()
}

func (h *HandlerMonitor) GetDashboardStats(c *gin.Context) {
	stats, err := h.svc.GetDashboardStats(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(stats).Send()
}

func (h *HandlerMonitor) GetTaskExecutionStats(c *gin.Context) {
	stats, err := h.svc.GetTaskExecutionStats(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(stats).Send()
}

func (h *HandlerMonitor) GenerateReport(c *gin.Context) {
	var req struct {
		StartDate string   `json:"start_date"`
		EndDate   string   `json:"end_date"`
		TaskIDs   []string `json:"task_ids"`
		Format    string   `json:"format"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		startDate = time.Now().AddDate(0, 0, -7)
	}
	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		endDate = time.Now()
	}
	endDate = endDate.Add(24*time.Hour - time.Second)

	web.OK(c).Data(gin.H{
		"start_date": startDate.Format("2006-01-02"),
		"end_date":   endDate.Format("2006-01-02"),
		"task_ids":   req.TaskIDs,
		"format":     req.Format,
		"generated":  true,
	}).Send()
}
