package sitemonitor

import (
	"strings"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

// ══ 任务 ══

func (h *HandlerMonitor) ListTasks(c *gin.Context) {
	req, ok := web.BindQuery[contract.TaskListReq](c)
	if !ok {
		return
	}
	scope := iamsdk.DataFilterScope(c, monitorFieldMapping)
	total, list, err := h.svc.ListTasks(c.Request.Context(), req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, list).Send()
}

func (h *HandlerMonitor) CreateTask(c *gin.Context) {
	var req struct {
		model.MonitorTask
		EnableAvailability  *bool `json:"enable_availability"`
		EnableBlacklink     *bool `json:"enable_blacklink"`
		EnableDomainHijack  *bool `json:"enable_domain_hijack"`
		EnableSensitiveFile *bool `json:"enable_sensitive_file"`
		EnableSensitiveWord *bool `json:"enable_sensitive_word"`
		EnableTamper        *bool `json:"enable_tamper"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	task := req.MonitorTask
	dims := map[string]*bool{
		"availability":   req.EnableAvailability,
		"blacklink":      req.EnableBlacklink,
		"domain_hijack":  req.EnableDomainHijack,
		"sensitive_file": req.EnableSensitiveFile,
		"sensitive_word": req.EnableSensitiveWord,
		"tamper":         req.EnableTamper,
	}
	for dim, enabled := range dims {
		if enabled != nil && *enabled {
			cfg := task.GetDimensionConfig(dim)
			if cfg == nil {
				cfg = model.JSONMap{"enabled": true}
			} else {
				cfg["enabled"] = true
			}
			task.SetDimensionConfig(dim, cfg)
		}
	}
	task.Enabled = true
	if task.ScheduleCron == "" {
		task.ScheduleEnabled = true
		task.ScheduleCron = "0 */1 * * * *"
	}
	if !task.ScheduleEnabled {
		task.ScheduleEnabled = true
	}
	user, _ := iamsdk.GetCurrentUser(c)
	task.CreatedBy = user.UserID
	task.OrganizeID = user.OrganizeID
	if err := h.svc.CreateTask(c.Request.Context(), &task); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	c.Set("_created_task_id", task.ID)
	web.OK(c).Data(gin.H{"id": task.ID}).Send()
}

func (h *HandlerMonitor) CreateTasksFromAssets(c *gin.Context) {
	var req struct {
		AssetIDs []string `json:"asset_ids" binding:"required,min=1"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	session, err := h.svc.GetDB().GetDBSession()
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	var assets []model.Asset
	if err := session.Where("id IN ?", req.AssetIDs).Find(&assets).Error; err != nil {
		web.Fail(c).Msg("查询资产失败").Err(err).Send()
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	ctx := c.Request.Context()

	type result struct {
		AssetID   string `json:"asset_id"`
		AssetName string `json:"asset_name"`
		TaskID    string `json:"task_id,omitempty"`
		Success   bool   `json:"success"`
		Error     string `json:"error,omitempty"`
		Skipped   bool   `json:"skipped"`
		Reason    string `json:"reason,omitempty"`
	}

	var results []result

	for _, asset := range assets {
		homepage := asset.URL
		if homepage == "" && asset.Domain != "" {
			homepage = "http://" + asset.Domain
		}
		if homepage == "" && asset.Address != "" {
			if strings.HasPrefix(asset.Address, "http") {
				homepage = asset.Address
			} else {
				homepage = "http://" + asset.Address
			}
		}

		if homepage == "" {
			results = append(results, result{
				AssetID: asset.ID, AssetName: asset.Name,
				Success: false, Skipped: true,
				Reason: "资产无URL/域名/地址，无法创建监测任务",
			})
			continue
		}

		var existCount int64
		session.Model(&model.MonitorTask{}).
			Where("target_homepage = ?", homepage).
			Count(&existCount)
		if existCount > 0 {
			results = append(results, result{
				AssetID: asset.ID, AssetName: asset.Name,
				Success: false, Skipped: true,
				Reason: "该URL已存在监测任务",
			})
			continue
		}

		task := model.MonitorTask{
			TaskName:            asset.Name,
			AssetID:             asset.ID,
			TargetHomepage:      homepage,
			TargetDomain:        asset.Domain,
			TargetIps:           asset.IPv4,
			Enabled:             true,
			ScheduleEnabled:     true,
			ScheduleCron:        "0 */1 * * * *",
			ConfigAvailability:  model.JSONMap{"enabled": true, "cron": "0 */1 * * * *"},
			ConfigDomainHijack:  model.JSONMap{"enabled": true, "cron": "0 0 */6 * * *"},
			ConfigTamper:        model.JSONMap{"enabled": true, "cron": "0 0 */2 * * *"},
			ConfigSensitiveWord: model.JSONMap{"enabled": true, "cron": "0 0 0 * * *"},
			ConfigSensitiveFile: model.JSONMap{"enabled": true, "cron": "0 0 0 * * *"},
			ConfigBlacklink:     model.JSONMap{"enabled": true, "cron": "0 0 */6 * * *"},
		}
		task.CreatedBy = user.UserID
		task.OrganizeID = user.OrganizeID

		if err := h.svc.CreateTask(ctx, &task); err != nil {
			results = append(results, result{
				AssetID: asset.ID, AssetName: asset.Name,
				Success: false, Error: err.Error(),
			})
			continue
		}

		c.Set("_created_task_id", task.ID)
		results = append(results, result{
			AssetID: asset.ID, AssetName: asset.Name,
			TaskID: task.ID, Success: true,
		})
	}

	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	web.OK(c).Data(gin.H{
		"total":   len(results),
		"success": successCount,
		"results": results,
	}).Send()
}

func (h *HandlerMonitor) GetTask(c *gin.Context) {
	id := c.Param("id")
	task, err := h.svc.GetTask(c.Request.Context(), id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(task).Send()
}

func (h *HandlerMonitor) UpdateTask(c *gin.Context) {
	id := c.Param("id")
	var req contract.TaskUpdateReq
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.UpdateTask(c.Request.Context(), id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) DeleteTask(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteTask(c.Request.Context(), id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
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

type runTaskReq struct {
	Dimensions []string `json:"dimensions"`
}

func (h *HandlerMonitor) RunTask(c *gin.Context) {
	id := c.Param("id")
	req, _ := web.BindJSON[runTaskReq](c)
	execIDs, err := h.svc.RunTask(c.Request.Context(), id, req.Dimensions)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"execution_ids": execIDs}).Send()
}

func (h *HandlerMonitor) BatchToggleEnabled(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.BatchToggleEnabled(c.Request.Context(), req.IDs); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) BatchUpdateConfigs(c *gin.Context) {
	var req contract.BatchUpdateConfigsReq
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.BatchUpdateConfigs(c.Request.Context(), req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) BatchSyncNames(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	updated, err := h.svc.BatchSyncNames(c.Request.Context(), req.IDs)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"updated": updated}).Send()
}

func (h *HandlerMonitor) BatchDeleteTasks(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.BatchDeleteTasks(c.Request.Context(), req.IDs); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ══ 调度 ══

func (h *HandlerMonitor) UpdateSchedule(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		ScheduleEnabled bool   `json:"schedule_enabled"`
		ScheduleCron    string `json:"schedule_cron"`
		ScheduleGroup   string `json:"schedule_group"`
		ScheduleJitter  int    `json:"schedule_jitter"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	updates := map[string]any{
		"schedule_enabled": req.ScheduleEnabled,
		"schedule_cron":    req.ScheduleCron,
		"schedule_group":   req.ScheduleGroup,
		"schedule_jitter":  req.ScheduleJitter,
	}
	if err := h.svc.UpdateTaskFields(c.Request.Context(), id, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"task_id": id, "synced": true}).Send()
}

func (h *HandlerMonitor) BatchUpdateSchedule(c *gin.Context) {
	var req struct {
		Ids             []string `json:"ids"`
		ScheduleEnabled *bool    `json:"schedule_enabled"`
		ScheduleCron    string   `json:"schedule_cron"`
		ScheduleGroup   string   `json:"schedule_group"`
		ScheduleJitter  *int     `json:"schedule_jitter"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if len(req.Ids) == 0 {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}
	updates := map[string]any{}
	if req.ScheduleEnabled != nil {
		updates["schedule_enabled"] = *req.ScheduleEnabled
	}
	if req.ScheduleCron != "" {
		updates["schedule_cron"] = req.ScheduleCron
	}
	if req.ScheduleGroup != "" {
		updates["schedule_group"] = req.ScheduleGroup
	}
	if req.ScheduleJitter != nil {
		updates["schedule_jitter"] = *req.ScheduleJitter
	}
	if len(updates) == 0 {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}
	if err := h.svc.BatchUpdateTaskFields(c.Request.Context(), req.Ids, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"count": len(req.Ids)}).Send()
}
