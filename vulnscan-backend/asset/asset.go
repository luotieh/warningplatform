package asset

import (
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Asset struct {
	handler       *HandlerAsset
	enrichHandler *EnrichHandler
}

func NewAsset(handler *HandlerAsset, enrichHandler *EnrichHandler) *Asset {
	return &Asset{handler: handler, enrichHandler: enrichHandler}
}

func (m *Asset) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/asset"), []authorize.Route{
		{
			Name: "资产管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "资产列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "资产统计", Path: "stats", Method: "GET", Handler: m.enrichHandler.AssetStats, Enabled: true},
				{Name: "资产聚合", Path: "aggregate", Method: "POST", Handler: m.enrichHandler.AggregateFromScans, Enabled: true},
				{Name: "批量分组", Path: "batch-assign", Method: "POST", Handler: m.enrichHandler.BatchAssignGroup, Enabled: true},
				{Name: "资产详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "资产关联详情", Path: ":id/enrich", Method: "GET", Handler: m.enrichHandler.AssetDetail, Enabled: true},
				{Name: "创建资产", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "批量导入", Path: "import", Method: "POST", Handler: m.handler.ImportAssets, Enabled: true},
				{Name: "导入模板", Path: "import/template", Method: "GET", Handler: m.handler.DownloadTemplate, Enabled: true},
				{Name: "批量编辑", Path: "batch-update", Method: "POST", Handler: m.handler.BatchUpdate, Enabled: true},
				{Name: "批量导出", Path: "export", Method: "GET", Handler: m.handler.Export, Enabled: true},
				{Name: "更新资产", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除资产", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "子资产列表", Path: ":id/children", Method: "GET", Handler: m.enrichHandler.ChildrenList, Enabled: true},
				{Name: "设置父资产", Path: ":id/parent", Method: "PUT", Handler: m.enrichHandler.SetParent, Enabled: true},
				{Name: "关联关系列表", Path: ":id/relations", Method: "GET", Handler: m.enrichHandler.RelationList, Enabled: true},
				{Name: "创建关联关系", Path: "relation", Method: "POST", Handler: m.enrichHandler.RelationCreate, Enabled: true},
				{Name: "删除关联关系", Path: "relation/:relationId", Method: "DELETE", Handler: m.enrichHandler.RelationDelete, Enabled: true},
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
