// Package asset 资产台账管理：CRUD、导入导出、富化、去重、风险计算。
package asset

import (
	"vulnscan-backend/scanrunner"

	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Asset struct {
	handler          *HandlerAsset
	enrichHandler    *EnrichHandler
	discoveryHandler *DiscoveryHandler
}

func NewAsset(handler *HandlerAsset, enrichHandler *EnrichHandler, discoveryHandler *DiscoveryHandler) *Asset {
	return &Asset{
		handler:          handler,
		enrichHandler:    enrichHandler,
		discoveryHandler: discoveryHandler,
	}
}

// BindScanRunner 在扫描调度器初始化后调用，使信息富化/资产探测走漏扫引擎。
func (m *Asset) BindScanRunner(session *gorm.DB, sched *scanrunner.Scheduler) {
	if m == nil {
		return
	}
	if m.enrichHandler != nil {
		m.enrichHandler.BindScanRunner(session, sched)
	}
	if m.discoveryHandler != nil {
		m.discoveryHandler.BindScanRunner(session, sched)
	}
}

func (m *Asset) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/asset"), []authorize.Route{
		{
			Name: "资产管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "资产列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "资产统计", Path: "stats", Method: "GET", Handler: m.enrichHandler.AssetStats, Enabled: true},
				{Name: "资产地域范围", Path: "region-scope", Method: "GET", Handler: m.enrichHandler.RegionScope, Enabled: true},
				{Name: "同步在线状态", Path: "sync-online-status", Method: "POST", Handler: m.enrichHandler.SyncOnlineStatus, Enabled: true},
				{Name: "资产聚合", Path: "aggregate", Method: "POST", Handler: m.enrichHandler.AggregateFromScans, Enabled: true},
				{Name: "子域名发现入库", Path: "import-scan-subdomains", Method: "POST", Handler: m.enrichHandler.ImportSubdomainsFromScan, Enabled: true},
				{Name: "修复子域名地址", Path: "repair-subdomain-addresses", Method: "POST", Handler: m.enrichHandler.RepairSubdomainAddresses, Enabled: true},
				{Name: "批量分组", Path: "batch-assign", Method: "POST", Handler: m.enrichHandler.BatchAssignGroup, Enabled: true},
				{Name: "资产详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "资产关联详情", Path: ":id/enrich", Method: "GET", Handler: m.enrichHandler.AssetDetail, Enabled: true},
				{Name: "创建资产", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "批量导入", Path: "import", Method: "POST", Handler: m.handler.ImportAssets, Enabled: true},
				{Name: "导入模板", Path: "import/template", Method: "GET", Handler: m.handler.DownloadTemplate, Enabled: true},
				{Name: "批量编辑", Path: "batch-update", Method: "POST", Handler: m.handler.BatchUpdate, Enabled: true},
				{Name: "批量删除", Path: "batch-delete", Method: "POST", Handler: m.handler.BatchDelete, Enabled: true},
				{Name: "批量导出", Path: "export", Method: "GET", Handler: m.handler.Export, Enabled: true},
				{Name: "更新资产", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除资产", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "资产去重", Path: "dedup", Method: "POST", Handler: m.enrichHandler.Dedup, Enabled: true},
				{Name: "网络空间入库", Path: "import-cyberspace", Method: "POST", Handler: m.enrichHandler.ImportFromCyberspace, Enabled: true},
				{Name: "信息富化", Path: ":id/enrich-run", Method: "POST", Handler: m.enrichHandler.EnrichAsset, Enabled: true},
				{Name: "批量富化", Path: "batch-enrich", Method: "POST", Handler: m.enrichHandler.BatchEnrich, Enabled: true},
				{Name: "风险重算", Path: ":id/risk-calc", Method: "POST", Handler: m.enrichHandler.RecalcRisk, Enabled: true},
				{Name: "全量风险重算", Path: "risk-recalc-all", Method: "POST", Handler: m.enrichHandler.RecalcAllRisk, Enabled: true},
				{Name: "风险趋势", Path: ":id/risk-trend", Method: "GET", Handler: m.enrichHandler.RiskTrend, Enabled: true},
				{Name: "风险排名", Path: "risk-ranking", Method: "GET", Handler: m.enrichHandler.RiskRanking, Enabled: true},
				{Name: "合规报告", Path: "compliance-report", Method: "GET", Handler: m.enrichHandler.ComplianceReport, Enabled: true},
			},
		},
		{
			Name: "资产探测", Enabled: true, Path: "discovery",
			Children: []authorize.Route{
				{Name: "探测任务列表", Path: "probes", Method: "GET", Handler: m.discoveryHandler.ListProbes, Enabled: true},
				{Name: "创建探测任务", Path: "probes", Method: "POST", Handler: m.discoveryHandler.CreateProbe, Enabled: true},
				{Name: "探测任务详情", Path: "probes/:id", Method: "GET", Handler: m.discoveryHandler.GetProbe, Enabled: true},
				{Name: "候选资产列表", Path: "probes/:id/candidates", Method: "GET", Handler: m.discoveryHandler.ListCandidates, Enabled: true},
				{Name: "同步候选", Path: "probes/:id/sync", Method: "POST", Handler: m.discoveryHandler.SyncCandidates, Enabled: true},
				{Name: "下发核验", Path: "probes/:id/candidates/verify", Method: "POST", Handler: m.discoveryHandler.VerifyCandidates, Enabled: true},
				{Name: "驳回候选", Path: "probes/:id/candidates/reject", Method: "POST", Handler: m.discoveryHandler.RejectCandidates, Enabled: true},
				{Name: "候选入库", Path: "probes/:id/candidates/import", Method: "POST", Handler: m.discoveryHandler.ImportCandidates, Enabled: true},
			},
		},
		{
			Name: "资产分组", Enabled: true, Path: "group",
			Children: []authorize.Route{
				{Name: "分组列表", Path: "list", Method: "GET", Handler: m.enrichHandler.GroupList, Enabled: true},
				{Name: "创建分组", Method: "POST", Handler: m.enrichHandler.GroupCreate, Enabled: true},
				{Name: "更新分组", Path: ":id", Method: "PUT", Handler: m.enrichHandler.GroupUpdate, Enabled: true},
				{Name: "删除分组", Path: ":id", Method: "DELETE", Handler: m.enrichHandler.GroupDelete, Enabled: true},
				{Name: "刷新动态分组", Path: ":id/refresh", Method: "POST", Handler: m.enrichHandler.GroupRefresh, Enabled: true},
			},
		},
	})
}
