package schedule

import (
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"vulnscan-backend/pkg/definition"
)

type Handler struct {
	svc  *ServiceSchedule
	cron *CronRunner
}

func NewHandler(svc *ServiceSchedule) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) SetCronRunner(cr *CronRunner) {
	h.cron = cr
}

type scheduleQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
}

func (h *Handler) List(c *gin.Context) {
	q, _ := web.BindQuery[scheduleQuery](c)

	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.svc.List(q, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) GetByID(c *gin.Context) {
	id := c.Param("id")
	item, err := h.svc.GetByID(id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) Create(c *gin.Context) {
	item, ok := web.BindJSON[model.ScanSchedule](c)
	if !ok {
		return
	}
	if err := h.svc.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) Update(c *gin.Context) {
	id := c.Param("id")
	updates, ok := web.BindJSON[map[string]any](c)
	if !ok {
		return
	}
	if err := h.svc.Update(id, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Delete(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

type toggleReq struct {
	Enabled bool `json:"enabled"`
}

func (h *Handler) Toggle(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[toggleReq](c)
	if !ok {
		return
	}
	if err := h.svc.Toggle(id, req.Enabled); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) RunNow(c *gin.Context) {
	id := c.Param("id")
	if h.cron == nil {
		web.Fail(c).Msg("调度器未就绪").Send()
		return
	}
	taskID, err := h.cron.RunNow(id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(gin.H{"task_id": taskID}).Send()
}
