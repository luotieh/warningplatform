package intel

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

type Intel struct {
	handler *Handler
}

func NewIntel(handler *Handler) *Intel {
	return &Intel{handler: handler}
}

func (m *Intel) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/intel"), []authorize.Route{
		{Name: "威胁情报", Enabled: true, Children: []authorize.Route{
			{Name: "CVE搜索", Path: "cve", Method: "GET", Handler: m.handler.SearchCVE, Enabled: true},
			{Name: "CVE详情", Path: "cve/:id", Method: "GET", Handler: m.handler.GetCVE, Enabled: true},
			{Name: "指纹匹配", Path: "match", Method: "GET", Handler: m.handler.MatchFingerprint, Enabled: true},
			{Name: "情报源列表", Path: "sources", Method: "GET", Handler: m.handler.GetSources, Enabled: true},
			{Name: "添加情报源", Path: "sources", Method: "POST", Handler: m.handler.AddSource, Enabled: true},
			{Name: "更新情报源", Path: "sources/:name", Method: "PUT", Handler: m.handler.UpdateSource, Enabled: true},
			{Name: "删除情报源", Path: "sources/:name", Method: "DELETE", Handler: m.handler.DeleteSource, Enabled: true},
			{Name: "立即同步", Path: "sync", Method: "POST", Handler: m.handler.SyncNow, Enabled: true},
			{Name: "统计概览", Path: "stats", Method: "GET", Handler: m.handler.GetStats, Enabled: true},
			{Name: "资产漏洞分析", Path: "analyze/:asset_id", Method: "GET", Handler: m.handler.AnalyzeAsset, Enabled: true},
			{Name: "批量漏洞分析", Path: "analyze/batch", Method: "POST", Handler: m.handler.BatchAnalyze, Enabled: true},
			{Name: "EPSS Top漏洞", Path: "epss/top", Method: "GET", Handler: m.handler.TopEPSS, Enabled: true},
			{Name: "趋势分析", Path: "trend", Method: "GET", Handler: m.handler.TrendAnalysis, Enabled: true},
			{Name: "IOC列表", Path: "ioc", Method: "GET", Handler: m.handler.ListIOC, Enabled: true},
			{Name: "创建IOC", Path: "ioc", Method: "POST", Handler: m.handler.CreateIOC, Enabled: true},
			{Name: "批量导入IOC", Path: "ioc/import", Method: "POST", Handler: m.handler.BatchImportIOC, Enabled: true},
			{Name: "删除IOC", Path: "ioc/:id", Method: "DELETE", Handler: m.handler.DeleteIOC, Enabled: true},
			{Name: "启停IOC", Path: "ioc/:id/toggle", Method: "POST", Handler: m.handler.ToggleIOC, Enabled: true},
			{Name: "IOC检测", Path: "ioc/check", Method: "POST", Handler: m.handler.CheckIOC, Enabled: true},
			{Name: "IOC扫描资产", Path: "ioc/scan-assets", Method: "POST", Handler: m.handler.ScanAssetsIOC, Enabled: true},
			{Name: "IOC统计", Path: "ioc/stats", Method: "GET", Handler: m.handler.GetIOCStats, Enabled: true},
			{Name: "查看Exploit", Path: "exploit/fetch", Method: "GET", Handler: m.handler.FetchExploit, Enabled: true},
			{Name: "搜索Exploit", Path: "exploit/search", Method: "GET", Handler: m.handler.SearchExploits, Enabled: true},
			{Name: "CPE映射列表", Path: "cpe-mappings", Method: "GET", Handler: m.handler.ListCPEMappings, Enabled: true},
			{Name: "添加CPE映射", Path: "cpe-mappings", Method: "POST", Handler: m.handler.AddCPEMapping, Enabled: true},
			{Name: "更新CPE映射", Path: "cpe-mappings/:product", Method: "PUT", Handler: m.handler.UpdateCPEMapping, Enabled: true},
			{Name: "删除CPE映射", Path: "cpe-mappings/:product", Method: "DELETE", Handler: m.handler.DeleteCPEMapping, Enabled: true},
			{Name: "订阅列表", Path: "subscriptions", Method: "GET", Handler: m.handler.ListSubscriptions, Enabled: true},
			{Name: "创建订阅", Path: "subscriptions", Method: "POST", Handler: m.handler.CreateSubscription, Enabled: true},
			{Name: "更新订阅", Path: "subscriptions/:id", Method: "PUT", Handler: m.handler.UpdateSubscription, Enabled: true},
			{Name: "删除订阅", Path: "subscriptions/:id", Method: "DELETE", Handler: m.handler.DeleteSubscription, Enabled: true},
			{Name: "测试订阅", Path: "subscriptions/:id/test", Method: "GET", Handler: m.handler.TestSubscription, Enabled: true},
		}},
	})
}
