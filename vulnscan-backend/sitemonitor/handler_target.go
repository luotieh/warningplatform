package sitemonitor

import (
	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

func (h *HandlerMonitor) CreateTarget(c *gin.Context) {
	req, ok := web.BindJSON[model.MonitorTarget](c)
	if !ok {
		return
	}
	if err := h.svc.CreateTarget(c.Request.Context(), &req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	c.Set("_created_target_id", req.ID)
	web.OK(c).Data(req).Send()
}

func (h *HandlerMonitor) UpdateTarget(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[contract.TargetUpdateReq](c)
	if !ok {
		return
	}
	if err := h.svc.UpdateTarget(c.Request.Context(), id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) DeleteTarget(c *gin.Context) {
	if err := h.svc.DeleteTarget(c.Request.Context(), c.Param("id")); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) GetTarget(c *gin.Context) {
	t, err := h.svc.GetTarget(c.Request.Context(), c.Param("id"))
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(t).Send()
}

func (h *HandlerMonitor) ListTargets(c *gin.Context) {
	req, ok := web.BindQuery[contract.TargetListReq](c)
	if !ok {
		return
	}
	scope := iamsdk.DataFilterScope(c, monitorFieldMapping)
	total, list, err := h.svc.ListTargets(c.Request.Context(), req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, list).Send()
}

func (h *HandlerMonitor) RunTarget(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[contract.RunTargetReq](c)
	if !ok {
		return
	}
	outcome, err := h.svc.RunTarget(c.Request.Context(), id, req.Dimensions)
	if err != nil {
		web.Fail(c).Err(err).Data(outcome).Send()
		return
	}
	web.OK(c).Data(outcome).Send()
}

func (h *HandlerMonitor) StartCrawl(c *gin.Context) {
	targetID := c.Param("id")
	req, ok := web.BindJSON[contract.CrawlStartReq](c)
	if !ok {
		return
	}
	job, err := h.svc.StartCrawl(c.Request.Context(), targetID, req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(job).Send()
}

func (h *HandlerMonitor) GetCrawlJob(c *gin.Context) {
	job, err := h.svc.GetCrawlJob(c.Request.Context(), c.Param("jobId"))
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(job).Send()
}

func (h *HandlerMonitor) ApplyCrawlPaths(c *gin.Context) {
	req, ok := web.BindJSON[contract.CrawlApplyReq](c)
	if !ok {
		return
	}
	n, err := h.svc.ApplyCrawlPaths(c.Request.Context(), c.Param("jobId"), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"created": n}).Send()
}

func (h *HandlerMonitor) CreateTasksFromAssets(c *gin.Context) {
	req, ok := web.BindJSON[contract.CreateTasksFromAssetsReq](c)
	if !ok {
		return
	}
	resp, createdIDs, err := h.svc.CreateTasksFromAssets(c.Request.Context(), req.AssetIDs)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	c.Set("_created_path_task_ids", createdIDs)
	web.OK(c).Data(resp).Send()
}

func (h *HandlerMonitor) FetchTaskMeta(c *gin.Context) {
	url := c.Query("url")
	if url == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}
	title, finalURL, err := h.svc.FetchTaskMeta(c.Request.Context(), url)
	if err != nil {
		web.OK(c).Data(gin.H{"title": "", "url": url, "error": err.Error()}).Send()
		return
	}
	web.OK(c).Data(gin.H{"title": title, "url": finalURL}).Send()
}

func (h *HandlerMonitor) UpdateTargetSchedule(c *gin.Context) {
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
	if err := h.svc.UpdateTarget(c.Request.Context(), id, contract.TargetUpdateReq{
		ScheduleEnabled: &enabled,
		ScheduleCron:    req.ScheduleCron,
	}); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"target_id": id}).Send()
}
