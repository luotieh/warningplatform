package schedule

import (
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Handler struct {
	db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

type scheduleQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
}

func (h *Handler) List(c *gin.Context) {
	var q scheduleQuery
	_ = c.ShouldBindQuery(&q)

	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	tx := h.db.Model(&model.ScanSchedule{}).Scopes(scope)
	if q.Keyword != "" {
		tx = tx.Where("name LIKE ?", "%"+q.Keyword+"%")
	}

	var count int64
	tx.Count(&count)
	if q.PageSize <= 0 {
		q.PageSize = 20
	}
	if q.Page <= 0 {
		q.Page = 1
	}

	var items []model.ScanSchedule
	tx.Order("created_at DESC").Offset((q.Page - 1) * q.PageSize).Limit(q.PageSize).Find(&items)
	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *Handler) GetByID(c *gin.Context) {
	id := c.Param("id")
	var item model.ScanSchedule
	if err := h.db.Where("id = ?", id).First(&item).Error; err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, item)
}

func (h *Handler) Create(c *gin.Context) {
	var item model.ScanSchedule
	if err := c.ShouldBindJSON(&item); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	item.ID = qulid.GenerateID()
	item.Status = model.ScheduleStatusIdle

	next := calcNextRun(item)
	item.NextRunAt = next

	if err := h.db.Create(&item).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, item)
}

func (h *Handler) Update(c *gin.Context) {
	id := c.Param("id")
	var updates map[string]any
	if err := c.ShouldBindJSON(&updates); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if err := h.db.Model(&model.ScanSchedule{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.db.Where("id = ?", id).Delete(&model.ScanSchedule{}).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) Toggle(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	updates := map[string]any{"enabled": req.Enabled}
	if req.Enabled {
		var item model.ScanSchedule
		if err := h.db.Where("id = ?", id).First(&item).Error; err == nil {
			item.Enabled = true
			next := calcNextRun(item)
			updates["next_run_at"] = next
		}
	}

	if err := h.db.Model(&model.ScanSchedule{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) RunNow(c *gin.Context) {
	id := c.Param("id")
	var item model.ScanSchedule
	if err := h.db.Where("id = ?", id).First(&item).Error; err != nil {
		web.Resp(c, web.NotFound)
		return
	}

	taskID := qulid.GenerateID()
	task := model.ScanTask{
		ID:           taskID,
		Name:         item.Name + " (手动触发)",
		TemplateID:   item.TemplateID,
		TemplateName: item.TemplateName,
		Type:         "full",
		Targets:      item.Targets,
		Config:       item.Config,
		Priority:     5,
		Status:       model.TaskStatusPending,
		ScheduleID:   item.ID,
		CreatedBy:    item.CreatedBy,
		OrganizeID:   item.OrganizeID,
	}
	if item.Config != nil {
		if p, ok := item.Config["profile"].(string); ok {
			task.Type = p
		}
	}

	if err := h.db.Create(&task).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	h.db.Model(&model.ScanSchedule{}).Where("id = ?", id).Updates(map[string]any{
		"last_task_id": taskID,
		"run_count":    gorm.Expr("run_count + 1"),
	})

	web.RespContent(c, web.Success, gin.H{"task_id": taskID})
}
