package scanrunner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"code.yt-security.com/public/access/authorize"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/definition"
)

type API struct {
	db        *gorm.DB
	scheduler *Scheduler
}

func NewAPI(db *gorm.DB, scheduler *Scheduler) *API {
	return &API{db: db, scheduler: scheduler}
}

func (a *API) RoutesWithGroup(group *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(group.Group("/scan"), []authorize.Route{
		{
			Name: "扫描管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "启动扫描", Path: "launch", Method: "POST", Handler: a.Launch, Enabled: true},
				{Name: "取消扫描", Path: "cancel/:id", Method: "POST", Handler: a.Cancel, Enabled: true},
				{Name: "重新运行", Path: "rerun/:id", Method: "POST", Handler: a.Rerun, Enabled: true},
				{Name: "扫描进度", Path: "progress/:id", Method: "GET", Handler: a.Progress, Enabled: true},
				{Name: "调度器状态", Path: "status", Method: "GET", Handler: a.Status, Enabled: true},
				{Name: "扫描模板列表", Path: "templates", Method: "GET", Handler: a.ListTemplates, Enabled: true},
				{Name: "扫描引擎预设", Path: "engine-presets", Method: "GET", Handler: a.ListEnginePresets, Enabled: true},
				{Name: "推导扫描参数", Path: "suggest-parameters", Method: "POST", Handler: a.SuggestParameters, Enabled: true},
				{Name: "引擎规则说明", Path: "engine-rules", Method: "GET", Handler: a.ListEngineRules, Enabled: true},
				{Name: "任务级参数说明", Path: "task-parameter-schema", Method: "GET", Handler: a.TaskParameterSchema, Enabled: true},
				{Name: "重载扫描知识库", Path: "knowledge/reload", Method: "POST", Handler: a.ReloadKnowledge, Enabled: true},
				{Name: "扫描事件流", Path: "events/:id", Method: "GET", Handler: a.Events, Enabled: true},
			},
		},
	})
}

type LaunchRequest struct {
	Name            string                 `json:"name" binding:"required"`
	Targets         []string               `json:"targets" binding:"required,min=1"`
	TemplateID      string                 `json:"template_id" binding:"required"`
	Parameters      map[string]interface{} `json:"parameters"`
	AssetIDs        []string               `json:"asset_ids"`
	ExecutorNodeIDs []string               `json:"executor_node_ids"`
	Priority        int                    `json:"priority"`
	ScheduleID      string                 `json:"schedule_id"`
}

func (a *API) Launch(c *gin.Context) {
	req, ok := web.BindJSON[LaunchRequest](c)
	if !ok {
		return
	}

	executorIDs := req.ExecutorNodeIDs
	if len(executorIDs) == 0 && req.Parameters != nil {
		if raw, ok := req.Parameters["executor_node_ids"]; ok {
			switch v := raw.(type) {
			case []string:
				executorIDs = v
			case []interface{}:
				for _, item := range v {
					executorIDs = append(executorIDs, fmt.Sprint(item))
				}
			}
		}
	}
	res, err := LaunchScan(a.db, a.scheduler, LaunchScanParams{
		Name:            req.Name,
		Targets:         req.Targets,
		TemplateID:      req.TemplateID,
		Parameters:      req.Parameters,
		AssetIDs:        req.AssetIDs,
		ExecutorNodeIDs: executorIDs,
		Priority:        req.Priority,
		ScheduleID:      req.ScheduleID,
	})
	if errors.Is(err, ErrTemplateNotFound) {
		web.Fail(c).Msg("模板不存在或已禁用").Send()
		return
	}
	if err != nil {
		slog.Error("[API] 创建扫描任务失败", "error", err)
		web.Err(c, definition.ScanCreateFailed).Send()
		return
	}

	task := res.Task
	if res.SplitMode {
		web.Succeed(c).Data(map[string]interface{}{
			"task_id":    task.ID,
			"name":       task.Name,
			"template":   task.TemplateName,
			"status":     task.Status,
			"sub_count":  res.SubCount,
			"split_mode": true,
		}).Send()
		return
	}

	web.Succeed(c).Data(map[string]interface{}{
		"task_id":  task.ID,
		"name":     task.Name,
		"template": task.TemplateName,
		"status":   task.Status,
	}).Send()
}

func (a *API) Rerun(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	res, err := RerunScan(a.db, a.scheduler, id)
	if errors.Is(err, ErrTemplateNotFound) {
		web.Fail(c).Msg("模板不存在或已禁用").Send()
		return
	}
	if err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}

	task := res.Task
	out := map[string]interface{}{
		"task_id":  task.ID,
		"name":     task.Name,
		"template": task.TemplateName,
		"status":   task.Status,
	}
	if res.SplitMode {
		out["split_mode"] = true
		out["sub_count"] = res.SubCount
	}
	web.Succeed(c).Data(out).Send()
}

func (a *API) Cancel(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	CancelScanTask(a.db, a.scheduler, id)
	web.Succeed(c).Send()
}

func (a *API) Progress(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	if p := a.scheduler.GetProgress(id); p != nil {
		web.Succeed(c).Data(p).Send()
		return
	}

	var task model.ScanTask
	if err := a.db.Where("id = ?", id).First(&task).Error; err != nil {
		web.Err(c, definition.ScanTaskNotFound).Send()
		return
	}

	web.Succeed(c).Data(TaskProgress{
		TaskID:         task.ID,
		Status:         task.Status,
		CurrentStage:   task.CurrentStage,
		Progress:       task.Progress,
		TotalTargets:   task.TotalTargets,
		ScannedTargets: task.ScannedTargets,
		VulnCritical:   task.VulnCritical,
		VulnHigh:       task.VulnHigh,
		VulnMedium:     task.VulnMedium,
		VulnLow:        task.VulnLow,
		VulnInfo:       task.VulnInfo,
	}).Send()
}

func (a *API) Status(c *gin.Context) {
	var queuedCount, runningCount, completedToday, failedToday, findingsToday int64

	a.db.Model(&model.ScanTask{}).Where("status = ?", model.TaskStatusQueued).Count(&queuedCount)
	a.db.Model(&model.ScanTask{}).Where("status = ?", model.TaskStatusRunning).Count(&runningCount)

	today := time.Now().Truncate(24 * time.Hour)
	a.db.Model(&model.ScanTask{}).Where("status = ? AND finished_at >= ?",
		model.TaskStatusCompleted, today).Count(&completedToday)
	a.db.Model(&model.ScanTask{}).Where("status = ? AND finished_at >= ?",
		model.TaskStatusFailed, today).Count(&failedToday)
	a.db.Model(&model.ScanFinding{}).Where("created_at >= ?", today).Count(&findingsToday)

	var avgDuration float64
	row := a.db.Model(&model.ScanTask{}).
		Select("AVG(JULIANDAY(finished_at) - JULIANDAY(started_at)) * 86400").
		Where("status = ? AND finished_at IS NOT NULL AND started_at IS NOT NULL AND finished_at >= ?",
			model.TaskStatusCompleted, today).Row()
	if row != nil {
		_ = row.Scan(&avgDuration)
	}

	web.Succeed(c).Data(map[string]interface{}{
		"active_runners":      a.scheduler.ActiveTasks(),
		"max_parallel":        a.scheduler.MaxParallel(),
		"memory_queue_len":    a.scheduler.QueueLen(),
		"queued_tasks":        queuedCount,
		"running_tasks":       runningCount,
		"completed_today":     completedToday,
		"failed_today":        failedToday,
		"findings_today":      findingsToday,
		"avg_task_duration_s": avgDuration,
		"cache_hit_rate":      a.scheduler.RunnerCacheHitRate(),
		"current_concurrency": a.scheduler.CurrentAdaptiveConcurrency(),
	}).Send()
}

func (a *API) ListTemplates(c *gin.Context) {
	var templates []model.ScanTemplate
	a.db.Where("enabled = ?", true).Order("builtin DESC, usage_count DESC").Find(&templates)

	type tmplItem struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Category    string   `json:"category"`
		Tags        []string `json:"tags"`
		Builtin     bool     `json:"builtin"`
	}

	var result []tmplItem
	for _, t := range templates {
		result = append(result, tmplItem{
			ID:          t.ID,
			Name:        t.Name,
			Description: t.Description,
			Category:    t.Category,
			Tags:        t.Tags,
			Builtin:     t.Builtin,
		})
	}

	web.Succeed(c).Data(result).Send()
}

func (a *API) ListEnginePresets(c *gin.Context) {
	web.Succeed(c).Data(ListScanEnginePresets()).Send()
}

func (a *API) Events(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	var task model.ScanTask
	if err := a.db.Where("id = ?", taskID).First(&task).Error; err != nil {
		web.Err(c, definition.ScanTaskNotFound).Send()
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Header("Access-Control-Allow-Origin", "*")

	flusher, ok := c.Writer.(interface{ Flush() })
	if !ok {
		c.String(500, "streaming unsupported")
		return
	}

	if task.Status == model.TaskStatusCompleted || task.Status == model.TaskStatusCancelled || task.Status == model.TaskStatusFailed || task.Status == model.TaskStatusPartial {
		writeSSE(c.Writer, "done", mustJSON(DonePayload{Status: task.Status}))
		flusher.Flush()
		return
	}

	ch := a.scheduler.SubscribeEvents(taskID)
	defer a.scheduler.UnsubscribeEvents(taskID, ch)

	if p := a.scheduler.GetProgress(taskID); p != nil {
		writeSSE(c.Writer, "progress", mustJSON(ProgressPayload{*p}))
		flusher.Flush()
	}

	ctx := c.Request.Context()
	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				writeSSE(c.Writer, string(EventDone), mustJSON(DonePayload{Status: "stream_closed"}))
				flusher.Flush()
				return
			}
			data, _ := json.Marshal(evt)
			writeSSE(c.Writer, string(evt.Type), data)
			flusher.Flush()
		case <-keepAlive.C:
			writeSSE(c.Writer, "ping", []byte(`{}`))
			flusher.Flush()
		}
	}
}

func writeSSE(w io.Writer, event string, data []byte) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
}
