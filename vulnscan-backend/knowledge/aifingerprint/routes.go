package aifingerprint

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

// Routes AI 指纹路由注册。
type Routes struct {
	handler *Handler
}

// NewRoutes 创建路由。
func NewRoutes(handler *Handler) *Routes {
	return &Routes{handler: handler}
}

// RoutesWithGroup 注册路由到 gin 分组。
func (r *Routes) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	routes := []authorize.Route{
		{
			Name: "AI指纹识别", Enabled: true,
			Children: []authorize.Route{
				{Name: "AI指纹分析", Path: "analyze", Method: "POST", Handler: r.handler.AnalyzeFingerprint, Enabled: true},
				{Name: "资产关联分析", Path: "relations", Method: "POST", Handler: r.handler.AnalyzeRelations, Enabled: true},
				{Name: "知识库统计", Path: "stats", Method: "GET", Handler: r.handler.KnowledgeStats, Enabled: true},
				{Name: "指纹学习", Path: "learn", Method: "POST", Handler: r.handler.Learn, Enabled: true},
			},
		},
	}
	return authorize.RegisterRoutes(e.Group("/ai-fingerprint"), routes)
}
