package fprule

import (
	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
	"vulnscan-backend/model"
)

type FPRule struct {
	handler *HandlerFPRule
}

func NewFPRule(handler *HandlerFPRule, database *db.DB) *FPRule {
	session, _ := database.GetDBSession()
	_ = session.AutoMigrate(&model.FPRule{})
	return &FPRule{handler: handler}
}

func (m *FPRule) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/fp-rules"), []authorize.Route{
		{
			Name: "误报管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "规则列表", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "规则详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "创建规则", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "更新规则", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除规则", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "启用禁用", Path: ":id/toggle", Method: "POST", Handler: m.handler.Toggle, Enabled: true},
				{Name: "标记误报", Path: "mark", Method: "POST", Handler: m.handler.Mark, Enabled: true},
			},
		},
	})
}
