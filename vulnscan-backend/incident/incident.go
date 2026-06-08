package incident

import (
	coreContract "vulnscan-backend/incident/core/core-contract"

	"vulnscan-backend/incident/audit"
	"vulnscan-backend/incident/comment"
	"vulnscan-backend/incident/core"
	"vulnscan-backend/incident/knowledge"
	"vulnscan-backend/incident/remediation"
	"vulnscan-backend/incident/sla"
	"vulnscan-backend/incident/stats"
	statsContract "vulnscan-backend/incident/stats/stats-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/access/authorize"
	"code.yt-security.com/public/core/db"
	"github.com/gin-gonic/gin"
)

type Incident struct {
	coreHandler        *core.HandlerCore
	auditHandler       *audit.HandlerAudit
	remediationHandler *remediation.HandlerRemediation
	slaHandler         *sla.HandlerSLA
	commentHandler     *comment.HandlerComment
	knowledgeHandler   *knowledge.HandlerKnowledge
	statsHandler       *stats.HandlerStats
}

func NewIncident(
	coreHandler *core.HandlerCore,
	auditHandler *audit.HandlerAudit,
	remediationHandler *remediation.HandlerRemediation,
	slaHandler *sla.HandlerSLA,
	commentHandler *comment.HandlerComment,
	knowledgeHandler *knowledge.HandlerKnowledge,
	statsHandler *stats.HandlerStats,
	database *db.DB,
) *Incident {
	initModels(database)
	return &Incident{
		coreHandler:        coreHandler,
		auditHandler:       auditHandler,
		remediationHandler: remediationHandler,
		slaHandler:         slaHandler,
		commentHandler:     commentHandler,
		knowledgeHandler:   knowledgeHandler,
		statsHandler:       statsHandler,
	}
}

func (m *Incident) CoreService() coreContract.ServiceCore {
	return m.coreHandler.CoreService()
}

func (m *Incident) StatsService() statsContract.ServiceStats {
	return m.statsHandler.ServiceStats()
}

func (m *Incident) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/incident"), []authorize.Route{
		{
			Name: "事件管理", Path: "incidents", Enabled: true,
			Children: []authorize.Route{
				{Name: "事件列表", Method: "GET", Handler: m.coreHandler.List, Enabled: true},
				{Name: "事件创建", Method: "POST", Handler: m.coreHandler.Create, Enabled: true},
				{Name: "事件报告预览", Path: ":id/report/preview", Method: "GET", Handler: m.statsHandler.PreviewIncidentReport, Enabled: true},
				{Name: "事件报告导出", Path: ":id/report", Method: "GET", Handler: m.statsHandler.ExportIncidentReport, Enabled: true},
				{Name: "事件详情", Path: ":id", Method: "GET", Handler: m.coreHandler.Detail, Enabled: true},
				{Name: "事件更新", Path: ":id", Method: "PUT", Handler: m.coreHandler.Update, Enabled: true},
				{Name: "事件删除", Path: ":id", Method: "DELETE", Handler: m.coreHandler.Delete, Enabled: true},
				{Name: "AI预审", Path: ":id/ai-pre-audit", Method: "POST", Handler: m.auditHandler.AIPreAudit, Enabled: true},
				{Name: "人工复核", Path: ":id/manual-audit", Method: "POST", Handler: m.auditHandler.ManualAudit, Enabled: true},
				{Name: "AI智能分类", Path: ":id/ai-classify", Method: "POST", Handler: m.auditHandler.AIClassify, Enabled: true},
				{Name: "提交整改", Path: ":id/remediation", Method: "POST", Handler: m.remediationHandler.SubmitRemediation, Enabled: true},
				{Name: "验证整改", Path: ":id/verify-remediation", Method: "POST", Handler: m.remediationHandler.VerifyRemediation, Enabled: true},
				{Name: "关闭事件", Path: ":id/close", Method: "POST", Handler: m.remediationHandler.CloseIncident, Enabled: true},
				{Name: "批量导入", Path: "import", Method: "POST", Handler: m.remediationHandler.BatchImport, Enabled: true},
				{Name: "导入模板下载", Path: "import-template", Method: "GET", Handler: m.remediationHandler.DownloadImportTemplate, Enabled: true},
				{Name: "批量导出", Path: "export-batch", Method: "POST", Handler: m.statsHandler.ExportBatch, Enabled: true},
				{Name: "单个导出", Path: "export-single", Method: "GET", Handler: m.statsHandler.ExportSingle, Enabled: true},
			},
		},
		{
			Name: "统计看板", Path: "dashboard", Enabled: true,
			Children: []authorize.Route{
				{Name: "统计概览", Path: "stats", Method: "GET", Handler: m.coreHandler.DashboardStats, Enabled: true},
				{Name: "事件类型分布", Path: "chart/type", Method: "GET", Handler: m.coreHandler.ChartByType, Enabled: true},
				{Name: "事件等级分布", Path: "chart/level", Method: "GET", Handler: m.coreHandler.ChartByLevel, Enabled: true},
				{Name: "事件趋势", Path: "chart/trend", Method: "GET", Handler: m.coreHandler.ChartByTrend, Enabled: true},
			},
		},
		{
			Name: "统计报表", Path: "stats", Enabled: true,
			Children: []authorize.Route{
				{Name: "整改统计", Path: "remediation", Method: "GET", Handler: m.statsHandler.RemediationStats, Enabled: true},
				{Name: "超期列表", Path: "overdue", Method: "GET", Handler: m.statsHandler.OverdueList, Enabled: true},
				{Name: "多维分析", Path: "analysis", Method: "GET", Handler: m.statsHandler.MultiDimAnalysis, Enabled: true},
				{Name: "报表生成", Path: "report", Method: "GET", Handler: m.statsHandler.GenerateReport, Enabled: true},
				{Name: "趋势预测", Path: "trend-prediction", Method: "GET", Handler: m.statsHandler.TrendPrediction, Enabled: true},
				{Name: "AI态势分析", Path: "ai-analysis", Method: "GET", Handler: m.statsHandler.AIAnalysis, Enabled: true},
			},
		},
		{
			Name: "事件操作日志", Path: "oplogs", Enabled: true,
			Children: []authorize.Route{
				{Name: "操作日志列表", Method: "GET", Handler: m.coreHandler.OplogList, Enabled: true},
				{Name: "接收操作回调", Path: "callback", Method: "POST", Handler: m.coreHandler.ReceiveOplogCallback, Enabled: true},
			},
		},
		{
			Name: "事件评论", Path: "comments", Enabled: true,
			Children: []authorize.Route{
				{Name: "创建评论", Method: "POST", Handler: m.commentHandler.CreateComment, Enabled: true},
				{Name: "评论列表", Method: "GET", Handler: m.commentHandler.ListComments, Enabled: true},
				{Name: "删除评论", Path: ":id", Method: "DELETE", Handler: m.commentHandler.DeleteComment, Enabled: true},
			},
		},
		{
			Name: "SLA管理", Path: "sla", Enabled: true,
			Children: []authorize.Route{
				{Name: "SLA概览", Path: "overview", Method: "GET", Handler: m.slaHandler.SLAOverview, Enabled: true},
				{Name: "设置SLA", Method: "POST", Handler: m.slaHandler.SetSLA, Enabled: true},
				{Name: "SLA检查", Path: "check", Method: "POST", Handler: m.slaHandler.CheckSLA, Enabled: true},
			},
		},
		{
			Name: "资产画像", Path: "assets", Enabled: true,
			Children: []authorize.Route{
				{Name: "资产画像", Path: "profile", Method: "GET", Handler: m.statsHandler.AssetProfile, Enabled: true},
				{Name: "资产列表", Path: "summary", Method: "GET", Handler: m.statsHandler.AssetSummary, Enabled: true},
			},
		},
		{
			Name: "知识库", Path: "knowledge", Enabled: true,
			Children: []authorize.Route{
				{Name: "文章列表", Method: "GET", Handler: m.knowledgeHandler.List, Enabled: true},
				{Name: "创建文章", Method: "POST", Handler: m.knowledgeHandler.Create, Enabled: true},
				{Name: "文章详情", Path: ":id", Method: "GET", Handler: m.knowledgeHandler.Detail, Enabled: true},
				{Name: "更新文章", Path: ":id", Method: "PUT", Handler: m.knowledgeHandler.Update, Enabled: true},
				{Name: "删除文章", Path: ":id", Method: "DELETE", Handler: m.knowledgeHandler.Delete, Enabled: true},
				{Name: "相似案例推荐", Path: "recommend", Method: "GET", Handler: m.knowledgeHandler.Recommend, Enabled: true},
				{Name: "事件归档", Path: "archive", Method: "POST", Handler: m.knowledgeHandler.Archive, Enabled: true},
			},
		},
	})
}

func initModels(database *db.DB) {
	session, _ := database.GetDBSession()
	_ = session.AutoMigrate(
		&model.SecurityIncident{},
		&model.IncidentAsset{},
		&model.IncidentMetadata{},
		&model.IncidentOperationLog{},
		&model.IncidentComment{},
		&model.IncidentDispatch{},
		&model.KnowledgeArticle{},
		&model.ThreatIntelRecord{},
	)
}
