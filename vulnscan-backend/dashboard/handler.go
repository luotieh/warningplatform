package dashboard

import (
	"context"
	"time"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	agg *Aggregator
}

func NewHandler(database *db.DB) *Handler {
	session, _ := database.GetDBSession()
	return &Handler{
		agg: NewAggregator(session),
	}
}

func (h *Handler) Overview(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	posture, err := h.agg.GetSecurityPosture(ctx)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(posture).Send()
}

func (h *Handler) VulnTrend(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	days := 30
	trend := h.agg.getVulnTrend(ctx, days)
	web.OK(c).Data(trend).Send()
}

func (h *Handler) TaskTrend(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	trend := h.agg.getTaskTrend(ctx, 30)
	web.OK(c).Data(trend).Send()
}

func (h *Handler) TopVulnAssets(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	assets := h.agg.getTopVulnAssets(ctx, 10)
	web.OK(c).Data(assets).Send()
}

func (h *Handler) TaskStatusDist(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	result := h.agg.GetTaskStatusDist(ctx)
	web.OK(c).Data(result).Send()
}

func (h *Handler) RecentActivity(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	activities := h.agg.GetRecentActivity(ctx)
	web.OK(c).Data(activities).Send()
}

type Dashboard struct {
	handler *Handler
}

func NewDashboard(handler *Handler) *Dashboard {
	return &Dashboard{handler: handler}
}

func (m *Dashboard) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/dashboard"), []authorize.Route{
		{
			Name: "仪表盘", Enabled: true,
			Children: []authorize.Route{
				{Name: "总览", Path: "overview", Method: "GET", Handler: m.handler.Overview, Enabled: true},
				{Name: "漏洞趋势", Path: "vuln-trend", Method: "GET", Handler: m.handler.VulnTrend, Enabled: true},
				{Name: "任务趋势", Path: "task-trend", Method: "GET", Handler: m.handler.TaskTrend, Enabled: true},
				{Name: "高危资产", Path: "top-vuln-assets", Method: "GET", Handler: m.handler.TopVulnAssets, Enabled: true},
				{Name: "任务分布", Path: "task-status", Method: "GET", Handler: m.handler.TaskStatusDist, Enabled: true},
				{Name: "最近活动", Path: "recent-activity", Method: "GET", Handler: m.handler.RecentActivity, Enabled: true},
			},
		},
	})
}
