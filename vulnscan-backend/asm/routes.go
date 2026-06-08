package asm

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

type ASM struct {
	handler *Handler
}

func NewASM(handler *Handler) *ASM {
	return &ASM{handler: handler}
}

func (m *ASM) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/asm"), []authorize.Route{
		{Name: "攻击面管理", Enabled: true, Children: []authorize.Route{
			{Name: "项目列表", Path: "projects", Method: "GET", Handler: m.handler.ListProjects, Enabled: true},
			{Name: "项目详情", Path: "projects/:id", Method: "GET", Handler: m.handler.GetProject, Enabled: true},
			{Name: "创建项目", Path: "projects", Method: "POST", Handler: m.handler.CreateProject, Enabled: true},
			{Name: "更新项目", Path: "projects/:id", Method: "PUT", Handler: m.handler.UpdateProject, Enabled: true},
			{Name: "删除项目", Path: "projects/:id", Method: "DELETE", Handler: m.handler.DeleteProject, Enabled: true},
			{Name: "添加种子", Path: "projects/:id/seeds", Method: "POST", Handler: m.handler.AddSeed, Enabled: true},
			{Name: "删除种子", Path: "projects/:id/seeds/:seed_id", Method: "DELETE", Handler: m.handler.DeleteSeed, Enabled: true},
			{Name: "执行发现", Path: "projects/:id/discover", Method: "POST", Handler: m.handler.RunDiscovery, Enabled: true},
			{Name: "发现状态", Path: "projects/:id/discovery-status", Method: "GET", Handler: m.handler.DiscoveryStatus, Enabled: true},
			{Name: "发现资产列表", Path: "projects/:id/assets", Method: "GET", Handler: m.handler.ListDiscoveredAssets, Enabled: true},
			{Name: "导出资产", Path: "projects/:id/assets/export", Method: "GET", Handler: m.handler.ExportAssets, Enabled: true},
			{Name: "变更记录", Path: "projects/:id/changes", Method: "GET", Handler: m.handler.ListChanges, Enabled: true},
			{Name: "告警规则列表", Path: "projects/:id/alert-rules", Method: "GET", Handler: m.handler.ListAlertRules, Enabled: true},
			{Name: "创建告警规则", Path: "projects/:id/alert-rules", Method: "POST", Handler: m.handler.CreateAlertRule, Enabled: true},
			{Name: "删除告警规则", Path: "projects/:id/alert-rules/:rule_id", Method: "DELETE", Handler: m.handler.DeleteAlertRule, Enabled: true},
			{Name: "暴露面报告", Path: "projects/:id/report", Method: "GET", Handler: m.handler.ExposureReport, Enabled: true},
		}},
	})
}
