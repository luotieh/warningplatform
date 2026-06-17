package sitemonitor

import (
	"vulnscan-backend/model"
	"vulnscan-backend/pkg/definition"
	"vulnscan-backend/sitemonitor/contract"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/web"
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
	web.Succeed(c).Data(req).Send()
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
	web.Succeed(c).Send()
}

func (h *HandlerMonitor) DeleteTarget(c *gin.Context) {
	if err := h.svc.DeleteTarget(c.Request.Context(), c.Param("id")); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerMonitor) BatchDeleteTargets(c *gin.Context) {
	req, ok := web.BindJSON[struct {
		IDs []string `json:"ids" binding:"required,min=1"`
	}](c)
	if !ok {
		return
	}
	if err := h.svc.BatchDeleteTargets(c.Request.Context(), req.IDs); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerMonitor) GetTarget(c *gin.Context) {
	t, err := h.svc.GetTarget(c.Request.Context(), c.Param("id"))
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(t).Send()
}

type targetWithAsset struct {
	model.MonitorTarget
	AssetName string `json:"asset_name,omitempty"`
	AssetOrg  string `json:"asset_org,omitempty"`
}

func (h *HandlerMonitor) ListTargets(c *gin.Context) {
	req, ok := web.BindQuery[contract.TargetListReq](c)
	if !ok {
		return
	}
	scope := definition.SafeDataFilterScope(c, monitorFieldMapping)
	total, list, err := h.svc.ListTargets(c.Request.Context(), req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	enriched := h.enrichTargetsWithAssetInfo(list)
	web.Succeed(c).List(total, enriched).Send()
}

func (h *HandlerMonitor) enrichTargetsWithAssetInfo(targets []model.MonitorTarget) []targetWithAsset {
	result := make([]targetWithAsset, len(targets))
	var assetIDs []string
	for i, t := range targets {
		result[i] = targetWithAsset{MonitorTarget: t}
		if t.AssetID != "" {
			assetIDs = append(assetIDs, t.AssetID)
		}
	}
	if len(assetIDs) == 0 {
		return result
	}

	session, err := h.db.GetDBSession()
	if err != nil {
		return result
	}
	type assetInfo struct {
		ID                string
		Name              string
		ConstructionOrgID string
	}
	var assets []assetInfo
	session.Model(&model.Asset{}).Select("id, name, construction_org_id").Where("id IN ?", assetIDs).Find(&assets)
	assetMap := make(map[string]*assetInfo, len(assets))
	for i := range assets {
		assetMap[assets[i].ID] = &assets[i]
	}

	var orgIDs []string
	for _, a := range assets {
		if a.ConstructionOrgID != "" {
			orgIDs = append(orgIDs, a.ConstructionOrgID)
		}
	}
	orgMap := make(map[string]string)
	if len(orgIDs) > 0 {
		type orgInfo struct {
			ID   string
			Name string
		}
		var orgs []orgInfo
		session.Model(&model.Organize{}).Select("id, name").Where("id IN ?", orgIDs).Find(&orgs)
		for _, o := range orgs {
			orgMap[o.ID] = o.Name
		}
	}

	for i := range result {
		if a, ok := assetMap[result[i].AssetID]; ok {
			result[i].AssetName = a.Name
			if orgName, ok := orgMap[a.ConstructionOrgID]; ok {
				result[i].AssetOrg = orgName
			}
		}
	}
	return result
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
	web.Succeed(c).Data(outcome).Send()
}

func (h *HandlerMonitor) StartCrawl(c *gin.Context) {
	targetID := c.Param("id")
	req, ok := web.BindJSON[contract.CrawlStartReq](c)
	if !ok {
		return
	}
	if user, ok := iamsdk.GetCurrentUser(c); ok && user != nil {
		req.CreatorID = user.UserID
	}
	job, err := h.svc.StartCrawl(c.Request.Context(), targetID, req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(job).Send()
}

func (h *HandlerMonitor) GetCrawlJob(c *gin.Context) {
	job, err := h.svc.GetCrawlJob(c.Request.Context(), c.Param("jobId"))
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	type crawlJobResp struct {
		*model.MonitorCrawlJob
		ScreenshotBaseURL string `json:"screenshot_base_url,omitempty"`
	}
	resp := crawlJobResp{MonitorCrawlJob: job}
	if impl, ok := h.svc.(*serviceMonitor); ok && impl.screenshotBaseURL != "" {
		resp.ScreenshotBaseURL = impl.screenshotBaseURL
	}
	web.Succeed(c).Data(resp).Send()
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
	web.Succeed(c).Data(gin.H{"created": n}).Send()
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
	web.Succeed(c).Data(resp).Send()
}

func (h *HandlerMonitor) FetchTaskMeta(c *gin.Context) {
	url := c.Query("url")
	if url == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}
	title, finalURL, err := h.svc.FetchTaskMeta(c.Request.Context(), url)
	if err != nil {
		web.Succeed(c).Data(gin.H{"title": "", "url": url, "error": err.Error()}).Send()
		return
	}
	web.Succeed(c).Data(gin.H{"title": title, "url": finalURL}).Send()
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
	web.Succeed(c).Data(gin.H{"target_id": id}).Send()
}
