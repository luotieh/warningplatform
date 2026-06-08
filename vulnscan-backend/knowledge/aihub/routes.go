package aihub

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

// Routes AI Hub 路由注册。
type Routes struct {
	handler *Handler
}

// NewRoutes 创建路由。
func NewRoutes(handler *Handler) *Routes {
	return &Routes{handler: handler}
}

// RoutesWithGroup 注册所有 AI 能力路由。
func (r *Routes) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	routes := []authorize.Route{
		{
			Name: "AI智能中心", Enabled: true,
			Children: []authorize.Route{
				// 指纹识别
				{Name: "AI指纹分析", Path: "fingerprint/analyze", Method: "POST", Handler: r.handler.AnalyzeFingerprint, Enabled: true},
				{Name: "资产关联分析", Path: "fingerprint/relations", Method: "POST", Handler: r.handler.AnalyzeRelations, Enabled: true},
				// 漏洞验证
				{Name: "AI漏洞验证", Path: "verify", Method: "POST", Handler: r.handler.VerifyVuln, Enabled: true},
				// Payload 生成
				{Name: "AI Payload生成", Path: "payload/generate", Method: "POST", Handler: r.handler.GeneratePayload, Enabled: true},
				// 爬虫决策
				{Name: "AI表单分析", Path: "crawl/form", Method: "POST", Handler: r.handler.AnalyzeForm, Enabled: true},
				{Name: "AI交互规划", Path: "crawl/interaction", Method: "POST", Handler: r.handler.PlanInteraction, Enabled: true},
				// 报告生成
				{Name: "AI漏洞报告", Path: "report/vuln", Method: "POST", Handler: r.handler.GenerateReport, Enabled: true},
				{Name: "AI管理摘要", Path: "report/summary", Method: "POST", Handler: r.handler.GenerateExecutiveSummary, Enabled: true},
				// 策略推荐
				{Name: "AI扫描策略", Path: "strategy/recommend", Method: "POST", Handler: r.handler.RecommendStrategy, Enabled: true},
				// 自然语言查询
				{Name: "自然语言查询", Path: "query", Method: "POST", Handler: r.handler.NLQuery, Enabled: true},
				// POC 生成
				{Name: "AI POC生成", Path: "poc/generate", Method: "POST", Handler: r.handler.GeneratePOC, Enabled: true},
				{Name: "AI POC优化", Path: "poc/improve", Method: "POST", Handler: r.handler.ImprovePOC, Enabled: true},
				// 合规问答
				{Name: "合规知识问答", Path: "compliance/ask", Method: "POST", Handler: r.handler.ComplianceAsk, Enabled: true},
				{Name: "漏洞合规映射", Path: "compliance/mapping", Method: "POST", Handler: r.handler.ComplianceMapping, Enabled: true},
			},
		},
	}
	return authorize.RegisterRoutes(e.Group("/ai"), routes)
}
