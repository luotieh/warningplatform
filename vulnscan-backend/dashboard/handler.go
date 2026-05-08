package dashboard

import (
	"context"
	"time"

	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

type Handler struct {
	db  *gorm.DB
	agg *Aggregator
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		db:  db,
		agg: NewAggregator(db),
	}
}

func (h *Handler) Overview(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	posture, err := h.agg.GetSecurityPosture(ctx)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, posture)
}

func (h *Handler) VulnTrend(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	days := 30
	trend := h.agg.getVulnTrend(ctx, days)
	web.RespContent(c, web.Success, trend)
}

func (h *Handler) TaskTrend(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	trend := h.agg.getTaskTrend(ctx, 30)
	web.RespContent(c, web.Success, trend)
}

func (h *Handler) TopVulnAssets(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	assets := h.agg.getTopVulnAssets(ctx, 10)
	web.RespContent(c, web.Success, assets)
}

func (h *Handler) TaskStatusDist(c *gin.Context) {
	var counts []struct {
		Status string
		Count  int
	}
	h.db.Model(&model.ScanTask{}).
		Select("status, count(*) as count").
		Group("status").
		Find(&counts)

	result := make(map[string]int, len(counts))
	for _, c := range counts {
		result[c.Status] = c.Count
	}
	web.RespContent(c, web.Success, result)
}

func (h *Handler) RecentActivity(c *gin.Context) {
	type activity struct {
		Type      string    `json:"type"`
		Title     string    `json:"title"`
		Detail    string    `json:"detail"`
		CreatedAt time.Time `json:"created_at"`
	}

	var activities []activity

	var recentTasks []model.ScanTask
	h.db.Order("created_at DESC").Limit(5).Find(&recentTasks)
	for _, t := range recentTasks {
		activities = append(activities, activity{
			Type:      "task",
			Title:     t.Name,
			Detail:    t.Status,
			CreatedAt: t.CreatedAt,
		})
	}

	var recentVulns []model.Vulnerability
	h.db.Order("created_at DESC").Limit(5).Find(&recentVulns)
	for _, v := range recentVulns {
		activities = append(activities, activity{
			Type:      "vuln",
			Title:     v.Title,
			Detail:    v.Severity,
			CreatedAt: v.CreatedAt,
		})
	}

	web.RespContent(c, web.Success, activities)
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
