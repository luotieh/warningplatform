package api

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

type Template struct {
	handler *Handler
}

func NewTemplate(handler *Handler) *Template {
	return &Template{handler: handler}
}

func (m *Template) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/template"), []authorize.Route{
		{
			Name: "扫描模板", Enabled: true,
			Children: []authorize.Route{
				{Name: "模板列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "模板详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "创建模板", Path: "", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "更新模板", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除模板", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "启停模板", Path: ":id/toggle", Method: "POST", Handler: m.handler.Toggle, Enabled: true},
				{Name: "初始化内置模板", Path: "seed-builtins", Method: "POST", Handler: m.handler.SeedBuiltins, Enabled: true},
				{Name: "内置模板列表", Path: "builtins", Method: "GET", Handler: m.handler.ListBuiltins, Enabled: true},
			},
		},
	})
}
