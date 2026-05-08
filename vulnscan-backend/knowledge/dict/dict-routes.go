package dict

import (
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Dict struct {
	handler *HandlerDict
}

func NewDict(handler *HandlerDict) *Dict {
	return &Dict{handler: handler}
}

func (m *Dict) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/dict"), []authorize.Route{
		{
			Name: "字典管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "字典列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "字典详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "创建字典", Path: "", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "更新字典", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除字典", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "字典条目", Path: ":id/entries", Method: "GET", Handler: m.handler.ListEntries, Enabled: true},
				{Name: "添加条目", Path: ":id/entries", Method: "POST", Handler: m.handler.AddEntry, Enabled: true},
				{Name: "删除条目", Path: ":id/entries/:entry_id", Method: "DELETE", Handler: m.handler.DeleteEntry, Enabled: true},
				{Name: "导入字典", Path: ":id/import", Method: "POST", Handler: m.handler.Import, Enabled: true},
				{Name: "导出字典", Path: ":id/export", Method: "GET", Handler: m.handler.Export, Enabled: true},
				{Name: "清空字典", Path: ":id/clear", Method: "POST", Handler: m.handler.Clear, Enabled: true},
			},
		},
	})
}
