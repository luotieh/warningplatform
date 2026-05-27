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
			if natsSvc != nil {
				natsSvc.svc = s
			}
		}
	}

	scheduler := NewCronScheduler(database, svcImpl)
	healthChecker := NewAgentHealthChecker(database)

	return &Monitor{
		handler:       handler,
		nats:          natsSvc,
		db:            database,
		scheduler:     scheduler,
		healthChecker: healthChecker,
	}
}

func (m *Monitor) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/sitemonitor"), []authorize.Route{
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
			{Name: "执行统计", Path: "execution-stats", Method: "GET", Handler: m.handler.GetTaskExecutionStats, Enabled: true},
			// 监测目标
			{Name: "目标列表", Path: "targets", Method: "GET", Handler: m.handler.ListTargets, Enabled: true},
			{Name: "创建目标", Path: "targets", Method: "POST", Handler: m.handleCreateTarget, Enabled: true},
			{Name: "从资产创建监测", Path: "targets/from-assets", Method: "POST", Handler: m.handleCreateTasksFromAssets, Enabled: true},
			{Name: "目标详情", Path: "targets/:id", Method: "GET", Handler: m.handler.GetTarget, Enabled: true},
			{Name: "更新目标", Path: "targets/:id", Method: "PUT", Handler: m.handleUpdateTarget, Enabled: true},
			{Name: "删除目标", Path: "targets/:id", Method: "DELETE", Handler: m.handleDeleteTarget, Enabled: true},
			{Name: "执行目标维度", Path: "targets/run/:id", Method: "POST", Handler: m.handler.RunTarget, Enabled: true},
			{Name: "更新目标调度", Path: "targets/:id/schedule", Method: "PUT", Handler: m.handleUpdateTargetSchedule, Enabled: true},
			{Name: "启动爬虫", Path: "targets/:id/crawl", Method: "POST", Handler: m.handler.StartCrawl, Enabled: true},
			{Name: "获取页面meta", Path: "fetch-meta", Method: "GET", Handler: m.handler.FetchTaskMeta, Enabled: true},
			// 路径任务
			{Name: "路径任务列表", Path: "path-tasks", Method: "GET", Handler: m.handler.ListPathTasks, Enabled: true},
			{Name: "创建路径任务", Path: "path-tasks", Method: "POST", Handler: m.handleCreatePathTask, Enabled: true},
			{Name: "路径任务详情", Path: "path-tasks/:id", Method: "GET", Handler: m.handler.GetPathTask, Enabled: true},
			{Name: "更新路径任务", Path: "path-tasks/:id", Method: "PUT", Handler: m.handleUpdatePathTask, Enabled: true},
			{Name: "删除路径任务", Path: "path-tasks/:id", Method: "DELETE", Handler: m.handleDeletePathTask, Enabled: true},
			{Name: "执行路径任务", Path: "path-tasks/run/:id", Method: "POST", Handler: m.handler.RunPathTask, Enabled: true},
			{Name: "路径任务趋势", Path: "path-tasks/:id/trend", Method: "GET", Handler: m.handler.GetTaskTrend, Enabled: true},
			{Name: "更新路径调度", Path: "path-tasks/:id/schedule", Method: "PUT", Handler: m.handleUpdatePathTaskSchedule, Enabled: true},
			{Name: "批量删除路径任务", Path: "path-tasks/batch/delete", Method: "DELETE", Handler: m.handler.BatchDeletePathTasks, Enabled: true},
			// 爬虫
			{Name: "爬虫任务详情", Path: "crawl-jobs/:jobId", Method: "GET", Handler: m.handler.GetCrawlJob, Enabled: true},
			{Name: "应用爬虫路径", Path: "crawl-jobs/:jobId/apply", Method: "POST", Handler: m.handler.ApplyCrawlPaths, Enabled: true},
			{Name: "下载导入模板", Path: "import/template", Method: "GET", Handler: m.handler.DownloadImportTemplate, Enabled: true},
			{Name: "导入监测", Path: "import", Method: "POST", Handler: m.handler.ImportTasks, Enabled: true},
			{Name: "导入结果", Path: "import/:importId", Method: "GET", Handler: m.handler.GetImportResult, Enabled: true},
			{Name: "导出导入结果", Path: "import/:importId/export", Method: "GET", Handler: m.handler.ExportImportResult, Enabled: true},
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
			{Name: "删除Agent", Path: "agents/:uuid", Method: "DELETE", Handler: m.handler.DeleteAgent, Enabled: true},
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

func (m *Monitor) handleCreateTarget(c *gin.Context) {
	m.handler.CreateTarget(c)
	if c.Writer.Status() < 300 {
		if v, ok := c.Get("_created_target_id"); ok {
			m.scheduler.SyncTargetFromDB(v.(string))
		}
	}
}

func (m *Monitor) handleCreateTasksFromAssets(c *gin.Context) {
	m.handler.CreateTasksFromAssets(c)
	if c.Writer.Status() < 300 {
		if v, ok := c.Get("_created_path_task_ids"); ok {
			if ids, ok2 := v.([]string); ok2 {
				for _, id := range ids {
					m.scheduler.SyncPathTaskFromDB(id)
				}
			}
		}
	}
}

func (m *Monitor) handleUpdateTarget(c *gin.Context) {
	m.handler.UpdateTarget(c)
	if c.Writer.Status() < 300 {
		m.scheduler.SyncTargetFromDB(c.Param("id"))
	}
}

func (m *Monitor) handleDeleteTarget(c *gin.Context) {
	id := c.Param("id")
	m.handler.DeleteTarget(c)
	if c.Writer.Status() < 300 {
		m.scheduler.RemoveTarget(id)
	}
}

func (m *Monitor) handleCreatePathTask(c *gin.Context) {
	m.handler.CreatePathTask(c)
	if c.Writer.Status() < 300 {
		if v, ok := c.Get("_created_path_task_id"); ok {
			m.scheduler.SyncPathTaskFromDB(v.(string))
		}
	}
}

func (m *Monitor) handleUpdatePathTask(c *gin.Context) {
	m.handler.UpdatePathTask(c)
	if c.Writer.Status() < 300 {
		m.scheduler.SyncPathTaskFromDB(c.Param("id"))
	}
}

func (m *Monitor) handleDeletePathTask(c *gin.Context) {
	id := c.Param("id")
	m.handler.DeletePathTask(c)
	if c.Writer.Status() < 300 {
		m.scheduler.RemovePathTask(id)
	}
}

func (m *Monitor) handleUpdateTargetSchedule(c *gin.Context) {
	m.handler.UpdateTargetSchedule(c)
	if c.Writer.Status() < 300 {
		m.scheduler.SyncTargetFromDB(c.Param("id"))
	}
}

func (m *Monitor) handleUpdatePathTaskSchedule(c *gin.Context) {
	m.handler.UpdatePathTaskSchedule(c)
	if c.Writer.Status() < 300 {
		m.scheduler.SyncPathTaskFromDB(c.Param("id"))
	}
}

type generateReportReq struct {
	StartDate string   `json:"start_date"`
	EndDate   string   `json:"end_date"`
	TaskIDs   []string `json:"task_ids"`
	Format    string   `json:"format"`
}

func (m *Monitor) handleGenerateReport(c *gin.Context) {
	req, ok := web.BindJSON[generateReportReq](c)
	if !ok {
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
		"active_entries": m.scheduler.ActiveCount(),
		"entries":        info,
	}).Send()
}

func (m *Monitor) GetNatsService() *NatsServiceImpl {
	return m.nats
}

// SetCrawlScreenshotUploader 注入爬虫截图上传能力
func (m *Monitor) SetCrawlScreenshotUploader(fn CrawlScreenshotUploader, baseURL string) {
	if m.handler != nil && m.handler.svc != nil {
		if s, ok := m.handler.svc.(*serviceMonitor); ok {
			s.SetCrawlScreenshotUploader(fn, baseURL)
		}
	}
}
