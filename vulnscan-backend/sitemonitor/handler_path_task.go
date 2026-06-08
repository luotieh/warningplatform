package sitemonitor

import (
	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

func (h *HandlerMonitor) CreatePathTask(c *gin.Context) {
	req, ok := web.BindJSON[model.MonitorPathTask](c)
	if !ok {
		return
	}
	if err := h.svc.CreatePathTask(c.Request.Context(), &req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	c.Set("_created_path_task_id", req.ID)
	web.Succeed(c).Data(req).Send()
}

func (h *HandlerMonitor) UpdatePathTask(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[contract.PathTaskUpdateReq](c)
	if !ok {
		return
	}
	if err := h.svc.UpdatePathTask(c.Request.Context(), id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerMonitor) DeletePathTask(c *gin.Context) {
	if err := h.svc.DeletePathTask(c.Request.Context(), c.Param("id")); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerMonitor) GetPathTask(c *gin.Context) {
	pt, err := h.svc.GetPathTask(c.Request.Context(), c.Param("id"))
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(pt).Send()
}

func (h *HandlerMonitor) ListPathTasks(c *gin.Context) {
	req, ok := web.BindQuery[contract.PathTaskListReq](c)
	if !ok {
		return
	}
	total, list, err := h.svc.ListPathTasks(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).List(total, list).Send()
}

func (h *HandlerMonitor) RunPathTask(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[contract.RunPathTaskReq](c)
	if !ok {
		return
	}
	outcome, err := h.svc.RunPathTask(c.Request.Context(), id, req.Dimensions)
	if err != nil {
		web.Fail(c).Err(err).Data(outcome).Send()
		return
	}
	web.Succeed(c).Data(outcome).Send()
}

func (h *HandlerMonitor) BatchDeletePathTasks(c *gin.Context) {
	req, ok := web.BindJSON[struct {
		IDs []string `json:"ids" binding:"required,min=1"`
	}](c)
	if !ok {
		return
	}
	if err := h.svc.BatchDeletePathTasks(c.Request.Context(), req.IDs); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerMonitor) UpdatePathTaskSchedule(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[struct {
		ScheduleEnabled bool   `json:"schedule_enabled"`
		ScheduleCron    string `json:"schedule_cron"`
		ScheduleJitter  int    `json:"schedule_jitter"`
	}](c)
	if !ok {
		return
	}
	enabled := req.ScheduleEnabled
	if err := h.svc.UpdatePathTask(c.Request.Context(), id, contract.PathTaskUpdateReq{
		ScheduleEnabled: &enabled,
		ScheduleCron:    req.ScheduleCron,
	}); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(gin.H{"path_task_id": id}).Send()
}
