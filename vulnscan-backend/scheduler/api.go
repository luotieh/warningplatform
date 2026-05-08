package scheduler

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
				{Name: "扫描策略列表", Path: "profiles", Method: "GET", Handler: a.ListProfiles, Enabled: true},
				{Name: "扫描事件流", Path: "events/:id", Method: "GET", Handler: a.Events, Enabled: true},
			},
		},
	})
}

type LaunchRequest struct {
	Name       string                 `json:"name" binding:"required"`
	Targets    []string               `json:"targets" binding:"required,min=1"`
	Profile    string                 `json:"profile"`
	Modules    []string               `json:"modules"`
	Parameters map[string]interface{} `json:"parameters"`
	Priority   int                    `json:"priority"`
	ScheduleID string                 `json:"schedule_id"`
}

func (a *API) Launch(c *gin.Context) {
	var req LaunchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	profile := req.Profile
	if profile == "" {
		profile = "full"
	}

	priority := req.Priority
	if priority <= 0 {
		priority = 5
	}

	config := model.JSONMap{
		"profile": profile,
	}
	if len(req.Modules) > 0 {
		mods := make([]interface{}, len(req.Modules))
		for i, m := range req.Modules {
			mods[i] = m
		}
		config["modules"] = mods
	}

	params := model.JSONMap{}
	for k, v := range req.Parameters {
		params[k] = v
	}

	task := model.ScanTask{
		ID:           qulid.GenerateID(),
		Name:         req.Name,
		Type:         profile,
		Profile:      profile,
		Targets:      req.Targets,
		Config:       config,
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
			web.Resp(c, definition.ScanCreateFailed)
			return
		}

		subTasks, err := splitter.Split(task)
		if err != nil {
			slog.Error("[API] 任务拆分失败", "error", err)
			web.Resp(c, definition.ScanCreateFailed)
			return
		}

		for i := range subTasks {
			a.scheduler.Enqueue(&subTasks[i])
		}

		web.RespContent(c, definition.ScanTaskCreated, map[string]interface{}{
			"task_id":    task.ID,
			"name":       task.Name,
			"status":     task.Status,
			"sub_count":  len(subTasks),
			"split_mode": true,
		})
		return
	}

	if err := a.db.Create(&task).Error; err != nil {
		web.Resp(c, definition.ScanCreateFailed)
		return
	}

	a.scheduler.Enqueue(&task)

	web.RespContent(c, definition.ScanTaskCreated, map[string]interface{}{
		"task_id": task.ID,
		"name":    task.Name,
		"status":  task.Status,
	})
}

func (a *API) Cancel(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if a.scheduler.CancelTask(id) {
		web.Resp(c, definition.ScanTaskCancelled)
		return
	}

	a.db.Model(&model.ScanTask{}).Where("id = ? AND status IN ?", id,
		[]string{model.TaskStatusQueued, model.TaskStatusPending}).
		Update("status", model.TaskStatusCancelled)

	web.Resp(c, definition.ScanTaskCancelled)
}

func (a *API) Progress(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if p := a.scheduler.GetProgress(id); p != nil {
		web.RespContent(c, web.Success, p)
		return
	}

	var task model.ScanTask
	if err := a.db.Where("id = ?", id).First(&task).Error; err != nil {
		web.Resp(c, definition.ScanTaskNotFound)
		return
	}

	web.RespContent(c, web.Success, TaskProgress{
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
	})
}

func (a *API) Status(c *gin.Context) {
	var queuedCount, runningCount, completedToday int64

	a.db.Model(&model.ScanTask{}).Where("status = ?", model.TaskStatusQueued).Count(&queuedCount)
	a.db.Model(&model.ScanTask{}).Where("status = ?", model.TaskStatusRunning).Count(&runningCount)

	today := time.Now().Truncate(24 * time.Hour)
	a.db.Model(&model.ScanTask{}).Where("status = ? AND finished_at >= ?",
		model.TaskStatusCompleted, today).Count(&completedToday)

	web.RespContent(c, web.Success, map[string]interface{}{
		"active_runners":   a.scheduler.ActiveTasks(),
		"max_parallel":     a.scheduler.maxParallel,
		"memory_queue_len": a.scheduler.QueueLen(),
		"queued_tasks":     queuedCount,
		"running_tasks":    runningCount,
		"completed_today":  completedToday,
	})
}

func (a *API) ListProfiles(c *gin.Context) {
	profiles := []map[string]interface{}{
		{"id": "quick", "name": "快速扫描", "description": "ICMP存活+端口扫描+服务识别+Web爬虫", "modules": 4},
		{"id": "recon", "name": "信息收集", "description": "全面信息收集(子域名/DNS/Web爬虫/指纹/WAF/JS分析/证书/API发现)", "modules": 14},
		{"id": "vuln", "name": "漏洞扫描", "description": "仅执行漏洞检测模块(SQLi/XSS/弱口令/SSRF)", "modules": 4},
		{"id": "full", "name": "全面扫描", "description": "信息收集+目录扫描+漏洞扫描+nuclei模板完整流程", "modules": 19},
	}

	web.RespContent(c, web.Success, profiles)
}

type ScanSchedule struct {
	ID         string            `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name       string            `gorm:"type:varchar(200);not null" json:"name"`
	CronExpr   string            `gorm:"type:varchar(100);not null" json:"cron_expr"`
	Profile    string            `gorm:"type:varchar(50)" json:"profile"`
	Targets    model.StringArray `gorm:"type:text" json:"targets"`
	Modules    model.StringArray `gorm:"type:text" json:"modules"`
	Parameters model.JSONMap     `gorm:"type:text" json:"parameters"`
	Enabled    bool              `gorm:"default:true" json:"enabled"`
	LastRunAt  *time.Time        `json:"last_run_at"`
	NextRunAt  *time.Time        `json:"next_run_at"`
	CreatedBy  string            `gorm:"type:varchar(64)" json:"created_by"`
	OrganizeID string            `gorm:"type:varchar(64);index" json:"organize_id"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

func (ScanSchedule) TableName() string { return "vs_scan_schedule" }

func (a *API) Events(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	var task model.ScanTask
	if err := a.db.Where("id = ?", taskID).First(&task).Error; err != nil {
		web.Resp(c, definition.ScanTaskNotFound)
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
