package sitemonitor

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/model"
	mc "vulnscan-backend/sitemonitor/sitemonitor-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

type HandlerMonitor struct {
	svc mc.ServiceMonitor
}

func NewHandlerMonitor(svc mc.ServiceMonitor) *HandlerMonitor {
	return &HandlerMonitor{svc: svc}
}

// ══ 词库 ══

func (h *HandlerMonitor) ListWordLibraries(c *gin.Context) {
	var req mc.WordLibraryListReq
	if err := c.ShouldBindQuery(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	total, list, err := h.svc.ListWordLibraries(c.Request.Context(), req)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContentWithNum(c, web.Success, total, list)
}

func (h *HandlerMonitor) CreateWordLibrary(c *gin.Context) {
	var dto struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if !web.ValidationJson(c, &dto) {
		return
	}
	lib := &model.MonitorWordLibrary{}
	lib.Name = dto.Name
	lib.Description = dto.Description
	if err := h.svc.CreateWordLibrary(c.Request.Context(), lib); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"id": lib.ID})
}

func (h *HandlerMonitor) GetWordLibrary(c *gin.Context) {
	id := c.Param("id")
	detail, err := h.svc.GetWordLibrary(c.Request.Context(), id)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, detail)
}

func (h *HandlerMonitor) UpdateWordLibrary(c *gin.Context) {
	id := c.Param("id")
	var req mc.WordLibraryUpdateReq
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.UpdateWordLibrary(c.Request.Context(), id, req); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) DeleteWordLibrary(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteWordLibrary(c.Request.Context(), id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

// ══ 词库分类 ══

func (h *HandlerMonitor) ListWordCategories(c *gin.Context) {
	id := c.Param("id")
	cats, err := h.svc.ListWordCategories(c.Request.Context(), id)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, cats)
}

func (h *HandlerMonitor) CreateWordCategory(c *gin.Context) {
	var dto struct {
		LibraryID   string `json:"library_id" binding:"required"`
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if !web.ValidationJson(c, &dto) {
		return
	}
	cat := &model.MonitorWordCategory{}
	cat.LibraryID = dto.LibraryID
	cat.Name = dto.Name
	cat.Description = dto.Description
	if err := h.svc.CreateWordCategory(c.Request.Context(), cat); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"id": cat.ID})
}

func (h *HandlerMonitor) UpdateWordCategory(c *gin.Context) {
	id := c.Param("id")
	var req mc.WordCategoryUpdateReq
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.UpdateWordCategory(c.Request.Context(), id, req); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) DeleteWordCategory(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteWordCategory(c.Request.Context(), id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

// ══ 词条 ══

func (h *HandlerMonitor) ListWordEntries(c *gin.Context) {
	var req mc.WordEntryListReq
	if err := c.ShouldBindQuery(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	total, list, err := h.svc.ListWordEntries(c.Request.Context(), req)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContentWithNum(c, web.Success, total, list)
}

func (h *HandlerMonitor) BatchCreateWordEntries(c *gin.Context) {
	var dtos []struct {
		CategoryID string `json:"category_id" binding:"required"`
		Word       string `json:"word" binding:"required"`
		Severity   string `json:"severity"`
	}
	if !web.ValidationJson(c, &dtos) {
		return
	}
	entries := make([]model.MonitorWordEntry, len(dtos))
	for i, d := range dtos {
		sev := d.Severity
		if sev == "" {
			sev = "medium"
		}
		entries[i] = model.MonitorWordEntry{
			CategoryID: d.CategoryID,
			Word:       d.Word,
			Severity:   sev,
		}
	}
	if err := h.svc.BatchCreateWordEntries(c.Request.Context(), entries); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) ImportWordEntries(c *gin.Context) {
	categoryID := c.PostForm("category_id")
	severity := c.PostForm("severity")
	if categoryID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if severity == "" {
		severity = "medium"
	}

	file, err := c.FormFile("file")
	if err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	f, err := file.Open()
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, 10*1024*1024))
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	content := string(data)
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	var words []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		word := strings.TrimSpace(parts[0])
		if word != "" {
			words = append(words, word)
		}
	}

	if len(words) == 0 {
		web.RespContent(c, web.Success, gin.H{"imported": 0, "message": "文件中未发现有效词条"})
		return
	}

	seen := make(map[string]bool)
	var entries []model.MonitorWordEntry
	for _, w := range words {
		lw := strings.ToLower(w)
		if seen[lw] {
			continue
		}
		seen[lw] = true
		entries = append(entries, model.MonitorWordEntry{
			CategoryID: categoryID,
			Word:       w,
			Severity:   severity,
		})
	}

	if err := h.svc.BatchCreateWordEntries(c.Request.Context(), entries); err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, gin.H{
		"imported":   len(entries),
		"duplicated": len(words) - len(entries),
	})
}

func (h *HandlerMonitor) DeleteWordEntries(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.DeleteWordEntries(c.Request.Context(), req.IDs); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

// ══ 文件库 ══

func (h *HandlerMonitor) ListFileLibraries(c *gin.Context) {
	var req mc.FileLibraryListReq
	if err := c.ShouldBindQuery(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	total, list, err := h.svc.ListFileLibraries(c.Request.Context(), req)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContentWithNum(c, web.Success, total, list)
}

func (h *HandlerMonitor) CreateFileLibrary(c *gin.Context) {
	var dto struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if !web.ValidationJson(c, &dto) {
		return
	}
	lib := &model.MonitorFileLibrary{}
	lib.Name = dto.Name
	lib.Description = dto.Description
	if err := h.svc.CreateFileLibrary(c.Request.Context(), lib); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"id": lib.ID})
}

func (h *HandlerMonitor) GetFileLibrary(c *gin.Context) {
	id := c.Param("id")
	detail, err := h.svc.GetFileLibrary(c.Request.Context(), id)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, detail)
}

func (h *HandlerMonitor) UpdateFileLibrary(c *gin.Context) {
	id := c.Param("id")
	var req mc.FileLibraryUpdateReq
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.UpdateFileLibrary(c.Request.Context(), id, req); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) DeleteFileLibrary(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteFileLibrary(c.Request.Context(), id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

// ══ 文件条目 ══

func (h *HandlerMonitor) ListFileEntries(c *gin.Context) {
	var req mc.FileEntryListReq
	if err := c.ShouldBindQuery(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	total, list, err := h.svc.ListFileEntries(c.Request.Context(), req)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContentWithNum(c, web.Success, total, list)
}

func (h *HandlerMonitor) BatchCreateFileEntries(c *gin.Context) {
	var dtos []struct {
		LibraryID string `json:"library_id" binding:"required"`
		Path      string `json:"path" binding:"required"`
		Mark      string `json:"mark"`
		Risk      string `json:"risk"`
	}
	if !web.ValidationJson(c, &dtos) {
		return
	}
	entries := make([]model.MonitorFileEntry, len(dtos))
	for i, d := range dtos {
		risk := d.Risk
		if risk == "" {
			risk = "high"
		}
		entries[i] = model.MonitorFileEntry{
			LibraryID: d.LibraryID,
			Path:      d.Path,
			Mark:      d.Mark,
			Risk:      risk,
		}
	}
	if err := h.svc.BatchCreateFileEntries(c.Request.Context(), entries); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) DeleteFileEntries(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.DeleteFileEntries(c.Request.Context(), req.IDs); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) ImportFileEntries(c *gin.Context) {
	libraryID := c.PostForm("library_id")
	risk := c.PostForm("risk")
	if libraryID == "" {
		web.Fail(c).Msg("library_id 必填").Send()
		return
	}
	if risk == "" {
		risk = "high"
	}

	file, _, err := c.Request.FormFile("file")
	if err != nil {
		web.Fail(c).Msg("请上传文件").Send()
		return
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		web.Fail(c).Msg("读取文件失败").Send()
		return
	}

	lines := strings.Split(string(raw), "\n")
	seen := make(map[string]bool)
	var entries []model.MonitorFileEntry
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		path := strings.TrimSpace(parts[0])
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true

		mark := ""
		entryRisk := risk
		if len(parts) >= 2 {
			mark = strings.TrimSpace(parts[1])
		}
		if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
			entryRisk = strings.TrimSpace(parts[2])
		}

		entries = append(entries, model.MonitorFileEntry{
			LibraryID: libraryID,
			Path:      path,
			Mark:      mark,
			Risk:      entryRisk,
		})
	}

	if len(entries) == 0 {
		web.OK(c).Data(gin.H{"imported": 0, "message": "文件中未发现有效路径"}).Send()
		return
	}

	duplicated := 0
	var toCreate []model.MonitorFileEntry
	for _, e := range entries {
		var count int64
		h.svc.CountFileEntryByPath(c.Request.Context(), e.LibraryID, e.Path, &count)
		if count > 0 {
			duplicated++
			continue
		}
		toCreate = append(toCreate, e)
	}

	if len(toCreate) > 0 {
		if err := h.svc.BatchCreateFileEntries(c.Request.Context(), toCreate); err != nil {
			web.Resp(c, web.InternalError)
			return
		}
	}

	web.OK(c).Data(gin.H{
		"imported":   len(toCreate),
		"duplicated": duplicated,
		"total":      len(entries),
	}).Send()
	web.Resp(c, web.Success)
}

// ══ 默认配置 ══

func (h *HandlerMonitor) ListDefaultConfigs(c *gin.Context) {
	configs, err := h.svc.ListDefaultConfigs(c.Request.Context())
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, configs)
}

func (h *HandlerMonitor) GetDefaultConfig(c *gin.Context) {
	dimension := c.Param("dimension")
	cfg, err := h.svc.GetDefaultConfig(c.Request.Context(), dimension)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, cfg)
}

func (h *HandlerMonitor) UpdateDefaultConfig(c *gin.Context) {
	dimension := c.Param("dimension")
	var req struct {
		ConfigJSON map[string]any `json:"config_json" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.UpdateDefaultConfig(c.Request.Context(), dimension, req.ConfigJSON); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

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
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, resp)
}

func (h *HandlerMonitor) GetDashboardStats(c *gin.Context) {
	stats, err := h.svc.GetDashboardStats(c.Request.Context())
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, stats)
}

func (h *HandlerMonitor) GetTaskExecutionStats(c *gin.Context) {
	stats, err := h.svc.GetTaskExecutionStats(c.Request.Context())
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, stats)
}

// ══ 任务 ══

func (h *HandlerMonitor) ListTasks(c *gin.Context) {
	var req mc.TaskListReq
	if err := c.ShouldBindQuery(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	total, list, err := h.svc.ListTasks(c.Request.Context(), req)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContentWithNum(c, web.Success, total, list)
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
		task.ScheduleCron = "0 */5 * * * *"
	}
	if !task.ScheduleEnabled {
		task.ScheduleEnabled = true
	}
	user, _ := iamsdk.GetCurrentUser(c)
	task.CreatedBy = user.UserID
	if err := h.svc.CreateTask(c.Request.Context(), &task); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	c.Set("_created_task_id", task.ID)
	web.RespContent(c, web.Success, gin.H{"id": task.ID})
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
		web.Resp(c, web.InternalError)
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

		taskName := asset.SystemName
		if taskName == "" {
			taskName = asset.Name
		}

		task := model.MonitorTask{
			TaskName:            taskName,
			AssetID:             asset.ID,
			TargetHomepage:      homepage,
			TargetDomain:        asset.Domain,
			TargetIps:           asset.IPv4,
			Enabled:             true,
			ScheduleEnabled:     true,
			ScheduleCron:        "0 */5 * * * *",
			ConfigAvailability:  model.JSONMap{"enabled": true, "cron": "0 */5 * * * *"},
			ConfigDomainHijack:  model.JSONMap{"enabled": true, "cron": "0 0 */6 * * *"},
			ConfigTamper:        model.JSONMap{"enabled": true, "cron": "0 0 */2 * * *"},
			ConfigSensitiveWord: model.JSONMap{"enabled": true, "cron": "0 0 0 * * *"},
			ConfigSensitiveFile: model.JSONMap{"enabled": true, "cron": "0 0 0 * * *"},
			ConfigBlacklink:     model.JSONMap{"enabled": true, "cron": "0 0 */6 * * *"},
		}
		task.CreatedBy = user.UserID

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
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, task)
}

func (h *HandlerMonitor) UpdateTask(c *gin.Context) {
	id := c.Param("id")
	var req mc.TaskUpdateReq
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.UpdateTask(c.Request.Context(), id, req); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) DeleteTask(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteTask(c.Request.Context(), id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) FetchTaskMeta(c *gin.Context) {
	url := c.Query("url")
	if url == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	title, finalURL, err := h.svc.FetchTaskMeta(c.Request.Context(), url)
	if err != nil {
		web.RespContent(c, web.Success, gin.H{"title": "", "url": url, "error": err.Error()})
		return
	}
	web.RespContent(c, web.Success, gin.H{"title": title, "url": finalURL})
}

func (h *HandlerMonitor) RunTask(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Dimensions []string `json:"dimensions"`
	}
	_ = c.ShouldBindJSON(&req)
	execIDs, err := h.svc.RunTask(c.Request.Context(), id, req.Dimensions)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"execution_ids": execIDs})
}

func (h *HandlerMonitor) BatchToggleEnabled(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.BatchToggleEnabled(c.Request.Context(), req.IDs); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) BatchUpdateConfigs(c *gin.Context) {
	var req mc.BatchUpdateConfigsReq
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.BatchUpdateConfigs(c.Request.Context(), req); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
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
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"updated": updated})
}

func (h *HandlerMonitor) BatchDeleteTasks(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.BatchDeleteTasks(c.Request.Context(), req.IDs); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

// ══ 导入 ══

func (h *HandlerMonitor) DownloadImportTemplate(c *gin.Context) {
	data, err := h.svc.GenerateImportTemplate(c.Request.Context())
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	c.Header("Content-Disposition", "attachment; filename=import_template.xlsx")
	c.Data(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", data)
}

func (h *HandlerMonitor) ImportTasks(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	defer file.Close()
	fileData, err := io.ReadAll(file)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	result, err := h.svc.ImportTasks(c.Request.Context(), fileData)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, result)
}

func (h *HandlerMonitor) GetImportResult(c *gin.Context) {
	importID := c.Param("importId")
	result, err := h.svc.GetImportResult(c.Request.Context(), importID)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, result)
}

func (h *HandlerMonitor) ExportImportResult(c *gin.Context) {
	importID := c.Param("importId")
	data, err := h.svc.ExportImportResult(c.Request.Context(), importID)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	c.Header("Content-Disposition", "attachment; filename=import_result.xlsx")
	c.Data(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", data)
}

// ══ 执行记录 ══

func (h *HandlerMonitor) ListExecutions(c *gin.Context) {
	var req mc.ExecutionListReq
	if err := c.ShouldBindQuery(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	total, list, err := h.svc.ListExecutions(c.Request.Context(), req)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContentWithNum(c, web.Success, total, list)
}

func (h *HandlerMonitor) GetExecutionDetail(c *gin.Context) {
	id := c.Param("id")
	detail, err := h.svc.GetExecutionDetail(c.Request.Context(), id)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, detail)
}

func (h *HandlerMonitor) DeleteExecution(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteExecution(c.Request.Context(), id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) BatchDeleteExecutions(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.BatchDeleteExecutions(c.Request.Context(), req.IDs); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) UpdateDisposition(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Disposition string `json:"disposition" binding:"required"`
		Remark      string `json:"remark"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.UpdateDisposition(c.Request.Context(), id, req.Disposition, req.Remark, user.UserID); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) BatchUpdateDisposition(c *gin.Context) {
	var req struct {
		IDs         []string `json:"ids" binding:"required"`
		Disposition string   `json:"disposition" binding:"required"`
		Remark      string   `json:"remark"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.BatchUpdateDisposition(c.Request.Context(), req.IDs, req.Disposition, req.Remark, user.UserID); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) GetEvidenceAsset(c *gin.Context) {
	id := c.Param("id")
	assetType := c.Param("type")
	data, contentType, err := h.svc.GetEvidenceAsset(c.Request.Context(), id, assetType)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	c.Data(http.StatusOK, contentType, data)
}

// ══ Agent ══

func (h *HandlerMonitor) ListAgents(c *gin.Context) {
	agents, err := h.svc.ListAgents(c.Request.Context())
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, agents)
}

func (h *HandlerMonitor) SyncAgentRules(c *gin.Context) {
	uuid := c.Param("uuid")
	result, err := h.svc.SyncAgentRules(c.Request.Context(), uuid)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, result)
}

func (h *HandlerMonitor) ShutdownAgent(c *gin.Context) {
	uuid := c.Param("uuid")
	result, err := h.svc.ShutdownAgent(c.Request.Context(), uuid)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, result)
}

// ══ 规则数据 ══

func (h *HandlerMonitor) ListRuleDataSummary(c *gin.Context) {
	list, err := h.svc.ListRuleDataSummary(c.Request.Context())
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, list)
}

func (h *HandlerMonitor) GetRuleData(c *gin.Context) {
	moduleKey := c.Param("moduleKey")
	data, err := h.svc.GetRuleData(c.Request.Context(), moduleKey)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, data)
}

func (h *HandlerMonitor) PutRuleData(c *gin.Context) {
	moduleKey := c.Param("moduleKey")
	var req struct {
		Data string `json:"data" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.PutRuleData(c.Request.Context(), moduleKey, req.Data); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) SyncAllRuleData(c *gin.Context) {
	if err := h.svc.SyncAllRuleData(c.Request.Context()); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerMonitor) ImportRuleData(c *gin.Context) {
	moduleKey := c.Param("moduleKey")
	if _, ok := model.MonitorModuleRegistry[moduleKey]; !ok {
		web.Fail(c).Msg("未知模块: " + moduleKey).Send()
		return
	}

	var req struct {
		Data  json.RawMessage `json:"data" binding:"required"`
		Merge bool            `json:"merge"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}

	var incoming map[string]any
	if err := json.Unmarshal(req.Data, &incoming); err != nil {
		web.Fail(c).Msg("JSON 格式无效: " + err.Error()).Send()
		return
	}

	if req.Merge {
		existing, _ := h.svc.GetRuleData(c.Request.Context(), moduleKey)
		if existing != nil && existing.Data != "" {
			var existingData map[string]any
			if err := json.Unmarshal([]byte(existing.Data), &existingData); err == nil {
				for key, val := range incoming {
					inArr, ok1 := val.([]any)
					exArr, ok2 := existingData[key].([]any)
					if ok1 && ok2 {
						existingData[key] = append(exArr, inArr...)
					} else {
						existingData[key] = val
					}
				}
				incoming = existingData
			}
		}
	}

	merged, _ := json.Marshal(incoming)
	if err := h.svc.PutRuleData(c.Request.Context(), moduleKey, string(merged)); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.OK(c).Data(gin.H{"module_key": moduleKey, "sections": len(incoming)}).Send()
}

func (h *HandlerMonitor) ResetDefaultRuleData(c *gin.Context) {
	InitDefaultRuleData(h.svc.GetDB())
	web.OK(c).Msg("默认规则数据已重置").Send()
}

// ══ 告警配置 ══

func (h *HandlerMonitor) GetAlertConfig(c *gin.Context) {
	cfg, err := h.svc.GetAlertConfig(c.Request.Context())
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, cfg)
}

func (h *HandlerMonitor) UpdateAlertConfig(c *gin.Context) {
	var cfg model.MonitorAlertConfig
	if !web.ValidationJson(c, &cfg) {
		return
	}
	if err := h.svc.UpdateAlertConfig(c.Request.Context(), &cfg); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
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
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"task_id": id, "synced": true})
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

	web.RespContent(c, web.Success, gin.H{
		"start_date": startDate.Format("2006-01-02"),
		"end_date":   endDate.Format("2006-01-02"),
		"task_ids":   req.TaskIDs,
		"format":     req.Format,
		"generated":  true,
	})
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
		web.Resp(c, web.ParamsMissingRequired)
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
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if err := h.svc.BatchUpdateTaskFields(c.Request.Context(), req.Ids, updates); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"count": len(req.Ids)})
}
