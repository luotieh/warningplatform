package scanrunner

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
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
				{Name: "扫描进度", Path: "progress/:id", Method: "GET", Handler: a.Progress, Enabled: true},
				{Name: "调度器状态", Path: "status", Method: "GET", Handler: a.Status, Enabled: true},
				{Name: "扫描模板列表", Path: "templates", Method: "GET", Handler: a.ListTemplates, Enabled: true},
				{Name: "扫描事件流", Path: "events/:id", Method: "GET", Handler: a.Events, Enabled: true},
			},
		},
	})
}

type LaunchRequest struct {
	Name       string                 `json:"name" binding:"required"`
	Targets    []string               `json:"targets" binding:"required,min=1"`
	TemplateID string                 `json:"template_id" binding:"required"`
	Parameters map[string]interface{} `json:"parameters"`
	Priority   int                    `json:"priority"`
	ScheduleID string                 `json:"schedule_id"`
}

func (a *API) Launch(c *gin.Context) {
	req, ok := web.BindJSON[LaunchRequest](c)
	if !ok {
		return
	}

	var tmpl model.ScanTemplate
	if err := a.db.Where("(id = ? OR code = ?) AND enabled = ?", req.TemplateID, req.TemplateID, true).First(&tmpl).Error; err != nil {
		web.Fail(c).Msg("模板不存在或已禁用").Send()
		return
	}

	priority := req.Priority
	if priority <= 0 {
		priority = 5
	}

	params := model.JSONMap{}
	for k, v := range req.Parameters {
		params[k] = v
	}

	task := model.ScanTask{
		ID:           qulid.GenerateID(),
		Name:         req.Name,
		TemplateID:   tmpl.ID,
		TemplateName: tmpl.Name,
		Targets:      req.Targets,
		Parameters:   params,
		Priority:     priority,
		Status:       model.TaskStatusQueued,
		TotalTargets: len(req.Targets),
		ScheduleID:   req.ScheduleID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	splitter := NewTaskSplitter(a.db)
	if splitter.ShouldSplit(req.Targets) {
		task.Status = "splitting"
		if err := a.db.Create(&task).Error; err != nil {
			web.Err(c, definition.ScanCreateFailed).Send()
			return
		}

		subTasks, err := splitter.Split(task)
		if err != nil {
			slog.Error("[API] 任务拆分失败", "error", err)
			web.Err(c, definition.ScanCreateFailed).Send()
			return
		}

		for i := range subTasks {
			a.scheduler.Enqueue(&subTasks[i])
		}

		web.OK(c).Data(map[string]interface{}{
			"task_id":    task.ID,
			"name":       task.Name,
			"template":   tmpl.Name,
			"status":     task.Status,
			"sub_count":  len(subTasks),
			"split_mode": true,
		}).Send()
		return
	}

	if err := a.db.Create(&task).Error; err != nil {
		web.Err(c, definition.ScanCreateFailed).Send()
		return
	}

	a.scheduler.Enqueue(&task)

	web.OK(c).Data(map[string]interface{}{
		"task_id":  task.ID,
		"name":     task.Name,
		"template": tmpl.Name,
		"status":   task.Status,
	}).Send()
}

func (a *API) Cancel(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	if a.scheduler.CancelTask(id) {
		web.OK(c).Send()
		return
	}

	a.db.Model(&model.ScanTask{}).Where("id = ? AND status IN ?", id,
		[]string{model.TaskStatusQueued, model.TaskStatusPending}).
		Update("status", model.TaskStatusCancelled)

	web.OK(c).Send()
}

func (a *API) Progress(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	if p := a.scheduler.GetProgress(id); p != nil {
		web.OK(c).Data(p).Send()
		return
	}

	var task model.ScanTask
	if err := a.db.Where("id = ?", id).First(&task).Error; err != nil {
		web.Err(c, definition.ScanTaskNotFound).Send()
		return
	}

	web.OK(c).Data(TaskProgress{
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
	var queuedCount, runningCount, completedToday int64

	a.db.Model(&model.ScanTask{}).Where("status = ?", model.TaskStatusQueued).Count(&queuedCount)
	a.db.Model(&model.ScanTask{}).Where("status = ?", model.TaskStatusRunning).Count(&runningCount)

	today := time.Now().Truncate(24 * time.Hour)
	a.db.Model(&model.ScanTask{}).Where("status = ? AND finished_at >= ?",
		model.TaskStatusCompleted, today).Count(&completedToday)

	web.OK(c).Data(map[string]interface{}{
		"active_runners":   a.scheduler.ActiveTasks(),
		"max_parallel":     a.scheduler.maxParallel,
		"memory_queue_len": a.scheduler.QueueLen(),
		"queued_tasks":     queuedCount,
		"running_tasks":    runningCount,
		"completed_today":  completedToday,
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

	web.OK(c).Data(result).Send()
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

	if task.Status == model.TaskStatusCompleted || task.Status == model.TaskStatusCancelled || task.Status == model.TaskStatusFailed {
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
