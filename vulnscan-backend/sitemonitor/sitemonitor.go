package sitemonitor

import (
	"context"
	"time"

	"vulnscan-backend/boot"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Monitor struct {
	handler       *HandlerMonitor
	nats          *NatsServiceImpl
	db            *db.DB
	agentAPI      *AgentAPI
	scheduler     *CronScheduler
	healthChecker *AgentHealthChecker
}

func NewMonitor(
	handler *HandlerMonitor,
	natsClient *boot.NatsClient,
	database *db.DB,
) *Monitor {
	var natsSvc *NatsServiceImpl
	if natsClient != nil && natsClient.IsConnected() {
		natsSvc = NewNatsServiceImpl(natsClient, database)
	}

	var svcImpl *serviceMonitor
	if handler.svc != nil {
		if s, ok := handler.svc.(*serviceMonitor); ok {
			s.nats = natsSvc
			svcImpl = s
		}
	}

	agentAPI := NewAgentAPI(database, svcImpl)
	scheduler := NewCronScheduler(database, svcImpl)
	healthChecker := NewAgentHealthChecker(database)

	return &Monitor{
		handler:       handler,
		nats:          natsSvc,
		db:            database,
		agentAPI:      agentAPI,
		scheduler:     scheduler,
		healthChecker: healthChecker,
	}
}

func (m *Monitor) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/monitor"), []authorize.Route{
		{Name: "网站监测", Enabled: true, Children: []authorize.Route{
			// 词库
			{Name: "词库列表", Path: "word-libraries", Method: "GET", Handler: m.handler.ListWordLibraries, Enabled: true},
			{Name: "创建词库", Path: "word-libraries", Method: "POST", Handler: m.handler.CreateWordLibrary, Enabled: true},
			{Name: "词库详情", Path: "word-libraries/:id", Method: "GET", Handler: m.handler.GetWordLibrary, Enabled: true},
			{Name: "更新词库", Path: "word-libraries/:id", Method: "PUT", Handler: m.handler.UpdateWordLibrary, Enabled: true},
			{Name: "删除词库", Path: "word-libraries/:id", Method: "DELETE", Handler: m.handler.DeleteWordLibrary, Enabled: true},
			// 词库分类
			{Name: "分类列表", Path: "word-categories/:id", Method: "GET", Handler: m.handler.ListWordCategories, Enabled: true},
			{Name: "创建分类", Path: "word-categories", Method: "POST", Handler: m.handler.CreateWordCategory, Enabled: true},
			{Name: "更新分类", Path: "word-categories/:id", Method: "PUT", Handler: m.handler.UpdateWordCategory, Enabled: true},
			{Name: "删除分类", Path: "word-categories/:id", Method: "DELETE", Handler: m.handler.DeleteWordCategory, Enabled: true},
			// 词条
			{Name: "词条列表", Path: "word-entries", Method: "GET", Handler: m.handler.ListWordEntries, Enabled: true},
			{Name: "批量创建词条", Path: "word-entries", Method: "POST", Handler: m.handler.BatchCreateWordEntries, Enabled: true},
			{Name: "批量删除词条", Path: "word-entries", Method: "DELETE", Handler: m.handler.DeleteWordEntries, Enabled: true},
			{Name: "导入词条", Path: "word-entries/import", Method: "POST", Handler: m.handler.ImportWordEntries, Enabled: true},
			// 文件库
			{Name: "文件库列表", Path: "file-libraries", Method: "GET", Handler: m.handler.ListFileLibraries, Enabled: true},
			{Name: "创建文件库", Path: "file-libraries", Method: "POST", Handler: m.handler.CreateFileLibrary, Enabled: true},
			{Name: "文件库详情", Path: "file-libraries/:id", Method: "GET", Handler: m.handler.GetFileLibrary, Enabled: true},
			{Name: "更新文件库", Path: "file-libraries/:id", Method: "PUT", Handler: m.handler.UpdateFileLibrary, Enabled: true},
			{Name: "删除文件库", Path: "file-libraries/:id", Method: "DELETE", Handler: m.handler.DeleteFileLibrary, Enabled: true},
			// 文件条目
			{Name: "文件条目列表", Path: "file-entries", Method: "GET", Handler: m.handler.ListFileEntries, Enabled: true},
			{Name: "批量创建文件条目", Path: "file-entries", Method: "POST", Handler: m.handler.BatchCreateFileEntries, Enabled: true},
			{Name: "批量删除文件条目", Path: "file-entries", Method: "DELETE", Handler: m.handler.DeleteFileEntries, Enabled: true},
			{Name: "导入文件条目", Path: "file-entries/import", Method: "POST", Handler: m.handler.ImportFileEntries, Enabled: true},
			// 默认配置
			{Name: "默认配置列表", Path: "default-configs", Method: "GET", Handler: m.handler.ListDefaultConfigs, Enabled: true},
			{Name: "默认配置详情", Path: "default-configs/:dimension", Method: "GET", Handler: m.handler.GetDefaultConfig, Enabled: true},
			{Name: "更新默认配置", Path: "default-configs/:dimension", Method: "PUT", Handler: m.handler.UpdateDefaultConfig, Enabled: true},
			// Dashboard
			{Name: "仪表盘统计", Path: "dashboard/stats", Method: "GET", Handler: m.handler.GetDashboardStats, Enabled: true},
			{Name: "执行统计", Path: "tasks/execution-stats", Method: "GET", Handler: m.handler.GetTaskExecutionStats, Enabled: true},
			// 任务
			{Name: "任务列表", Path: "tasks", Method: "GET", Handler: m.handler.ListTasks, Enabled: true},
			{Name: "创建任务", Path: "tasks", Method: "POST", Handler: m.handleCreateTask, Enabled: true},
			{Name: "从资产创建任务", Path: "tasks/from-assets", Method: "POST", Handler: m.handleCreateFromAssets, Enabled: true},
			{Name: "任务详情", Path: "tasks/:id", Method: "GET", Handler: m.handler.GetTask, Enabled: true},
			{Name: "任务趋势", Path: "tasks/:id/trend", Method: "GET", Handler: m.handler.GetTaskTrend, Enabled: true},
			{Name: "更新任务", Path: "tasks/:id", Method: "PUT", Handler: m.handleUpdateTask, Enabled: true},
			{Name: "删除任务", Path: "tasks/:id", Method: "DELETE", Handler: m.handleDeleteTask, Enabled: true},
			{Name: "获取页面meta", Path: "tasks/fetch-meta", Method: "GET", Handler: m.handler.FetchTaskMeta, Enabled: true},
			{Name: "手动执行任务", Path: "tasks/run/:id", Method: "POST", Handler: m.handler.RunTask, Enabled: true},
			{Name: "批量切换启用", Path: "tasks/batch/toggle-enabled", Method: "PUT", Handler: m.handleBatchToggleEnabled, Enabled: true},
			{Name: "批量更新配置", Path: "tasks/batch/update-configs", Method: "PUT", Handler: m.handleBatchUpdateConfigs, Enabled: true},
			{Name: "批量同步名称", Path: "tasks/batch/sync-names", Method: "PUT", Handler: m.handler.BatchSyncNames, Enabled: true},
			{Name: "批量删除任务", Path: "tasks/batch/delete", Method: "DELETE", Handler: m.handler.BatchDeleteTasks, Enabled: true},
			// 导入
			{Name: "下载导入模板", Path: "tasks/import/template", Method: "GET", Handler: m.handler.DownloadImportTemplate, Enabled: true},
			{Name: "导入任务", Path: "tasks/import", Method: "POST", Handler: m.handler.ImportTasks, Enabled: true},
			{Name: "导入结果", Path: "tasks/import/result/:importId", Method: "GET", Handler: m.handler.GetImportResult, Enabled: true},
			{Name: "导出导入结果", Path: "tasks/import/result/:importId/export", Method: "GET", Handler: m.handler.ExportImportResult, Enabled: true},
			// 执行记录
			{Name: "执行记录列表", Path: "executions", Method: "GET", Handler: m.handler.ListExecutions, Enabled: true},
			{Name: "执行记录详情", Path: "executions/:id", Method: "GET", Handler: m.handler.GetExecutionDetail, Enabled: true},
			{Name: "删除执行记录", Path: "executions/:id", Method: "DELETE", Handler: m.handler.DeleteExecution, Enabled: true},
			{Name: "批量删除执行记录", Path: "executions/batch/delete", Method: "DELETE", Handler: m.handler.BatchDeleteExecutions, Enabled: true},
			{Name: "更新处置状态", Path: "executions/:id/disposition", Method: "PUT", Handler: m.handler.UpdateDisposition, Enabled: true},
			{Name: "批量更新处置", Path: "executions/batch/disposition", Method: "PUT", Handler: m.handler.BatchUpdateDisposition, Enabled: true},
			{Name: "获取证据文件", Path: "executions/:id/evidence/:type", Method: "GET", Handler: m.handler.GetEvidenceAsset, Enabled: true},
			// Agent
			{Name: "Agent列表", Path: "agents", Method: "GET", Handler: m.handler.ListAgents, Enabled: true},
			{Name: "同步Agent规则", Path: "agents/:uuid/sync-rules", Method: "POST", Handler: m.handler.SyncAgentRules, Enabled: true},
			{Name: "关闭Agent", Path: "agents/:uuid/shutdown", Method: "POST", Handler: m.handler.ShutdownAgent, Enabled: true},
			// 规则数据
			{Name: "规则数据列表", Path: "rule-data", Method: "GET", Handler: m.handler.ListRuleDataSummary, Enabled: true},
			{Name: "规则数据详情", Path: "rule-data/:moduleKey", Method: "GET", Handler: m.handler.GetRuleData, Enabled: true},
			{Name: "更新规则数据", Path: "rule-data/:moduleKey", Method: "PUT", Handler: m.handler.PutRuleData, Enabled: true},
			{Name: "同步全部规则", Path: "rule-data/sync", Method: "POST", Handler: m.handler.SyncAllRuleData, Enabled: true},
			{Name: "导入规则数据", Path: "rule-data/:moduleKey/import", Method: "POST", Handler: m.handler.ImportRuleData, Enabled: true},
			{Name: "重置默认规则", Path: "rule-data/reset-defaults", Method: "POST", Handler: m.handler.ResetDefaultRuleData, Enabled: true},
			// 告警配置
			{Name: "告警配置详情", Path: "alert-config", Method: "GET", Handler: m.handler.GetAlertConfig, Enabled: true},
			{Name: "更新告警配置", Path: "alert-config", Method: "PUT", Handler: m.handler.UpdateAlertConfig, Enabled: true},
			// 调度
			{Name: "更新任务调度", Path: "tasks/:id/schedule", Method: "PUT", Handler: m.handleUpdateSchedule, Enabled: true},
			{Name: "批量更新调度", Path: "tasks/batch/update-schedule", Method: "PUT", Handler: m.handleBatchUpdateSchedule, Enabled: true},
			{Name: "调度概览", Path: "schedule/overview", Method: "GET", Handler: m.handleScheduleOverview, Enabled: true},
			// 报告
			{Name: "生成报告", Path: "reports/generate", Method: "POST", Handler: m.handleGenerateReport, Enabled: true},
		}},
	})
}

func (m *Monitor) StartScheduler() {
	if m.scheduler != nil {
		m.scheduler.Start(context.Background())
	}
	if m.healthChecker != nil {
		m.healthChecker.Start(context.Background())
	}
}

func (m *Monitor) StopScheduler() {
	if m.healthChecker != nil {
		m.healthChecker.Stop()
	}
	if m.scheduler != nil {
		m.scheduler.Stop()
	}
}

func (m *Monitor) GetScheduler() *CronScheduler {
	return m.scheduler
}

func (m *Monitor) handleCreateTask(c *gin.Context) {
	m.handler.CreateTask(c)
	if c.Writer.Status() < 300 {
		if v, ok := c.Get("_created_task_id"); ok {
			m.scheduler.SyncTaskFromDB(v.(string))
		}
	}
}

func (m *Monitor) handleCreateFromAssets(c *gin.Context) {
	m.handler.CreateTasksFromAssets(c)
	if c.Writer.Status() < 300 {
		m.scheduler.ReloadAll()
	}
}

func (m *Monitor) handleUpdateTask(c *gin.Context) {
	m.handler.UpdateTask(c)
	if c.Writer.Status() < 300 {
		taskID := c.Param("id")
		m.scheduler.SyncTaskFromDB(taskID)
	}
}

func (m *Monitor) handleDeleteTask(c *gin.Context) {
	taskID := c.Param("id")
	m.handler.DeleteTask(c)
	if c.Writer.Status() < 300 {
		m.scheduler.RemoveTask(taskID)
	}
}

func (m *Monitor) handleBatchToggleEnabled(c *gin.Context) {
	m.handler.BatchToggleEnabled(c)
	if c.Writer.Status() < 300 {
		m.scheduler.ReloadAll()
	}
}

func (m *Monitor) handleBatchUpdateConfigs(c *gin.Context) {
	m.handler.BatchUpdateConfigs(c)
	if c.Writer.Status() < 300 {
		m.scheduler.ReloadAll()
	}
}

func (m *Monitor) handleUpdateSchedule(c *gin.Context) {
	m.handler.UpdateSchedule(c)
	if c.Writer.Status() < 300 {
		taskID := c.Param("id")
		m.scheduler.SyncTaskFromDB(taskID)
	}
}

func (m *Monitor) handleBatchUpdateSchedule(c *gin.Context) {
	m.handler.BatchUpdateSchedule(c)
}

func (m *Monitor) handleGenerateReport(c *gin.Context) {
	var req struct {
		StartDate string   `json:"start_date"`
		EndDate   string   `json:"end_date"`
		TaskIDs   []string `json:"task_ids"`
		Format    string   `json:"format"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Err(c, web.CodeDataParamsValidatorError).Msg("请求参数无效").Send()
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

	gen := NewReportGenerator(m.db)
	report, err := gen.GenerateReport(c.Request.Context(), startDate, endDate, req.TaskIDs)
	if err != nil {
		web.Fail(c).Msg("生成报告失败").Err(err).Send()
		return
	}

	if req.Format == "html" {
		htmlBytes, err := gen.RenderHTML(report)
		if err != nil {
			web.Fail(c).Msg("渲染HTML报告失败").Err(err).Send()
			return
		}
		c.Data(200, "text/html; charset=utf-8", htmlBytes)
		return
	}

	web.OK(c).Data(report).Send()
}

func (m *Monitor) handleScheduleOverview(c *gin.Context) {
	info := m.scheduler.GetScheduleInfo()
	web.OK(c).Data(gin.H{
		"active_tasks": m.scheduler.ActiveCount(),
		"entries":      info,
	}).Send()
}

func (m *Monitor) RegisterAgentAPI(e *gin.Engine, pathPrefix string) {
	m.agentAPI.RegisterRoutes(e, pathPrefix)
}

func (m *Monitor) GetNatsService() *NatsServiceImpl {
	return m.nats
}
