package datalib

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

type DataLib struct {
	handler *HandlerDataLib
}

func NewDataLib(handler *HandlerDataLib) *DataLib {
	return &DataLib{handler: handler}
}

func (m *DataLib) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/data-libraries"), []authorize.Route{
		{
			Name: "数据字典管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "字典列表", Path: "", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "字典详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "创建字典", Path: "", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "更新字典", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除字典", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},

				{Name: "条目列表", Path: ":id/entries", Method: "GET", Handler: m.handler.ListEntries, Enabled: true},
				{Name: "条目详情", Path: ":id/entries/:entry_id", Method: "GET", Handler: m.handler.GetEntry, Enabled: true},
				{Name: "添加条目", Path: ":id/entries", Method: "POST", Handler: m.handler.AddEntry, Enabled: true},
				{Name: "更新条目", Path: ":id/entries/:entry_id", Method: "PUT", Handler: m.handler.UpdateEntry, Enabled: true},
				{Name: "删除条目", Path: ":id/entries/:entry_id", Method: "DELETE", Handler: m.handler.DeleteEntry, Enabled: true},
				{Name: "批量添加", Path: ":id/entries/batch", Method: "POST", Handler: m.handler.BatchAddEntries, Enabled: true},

				{Name: "导入字典", Path: ":id/import", Method: "POST", Handler: m.handler.Import, Enabled: true},
				{Name: "导出字典", Path: ":id/export", Method: "GET", Handler: m.handler.Export, Enabled: true},
				{Name: "清空字典", Path: ":id/clear", Method: "POST", Handler: m.handler.Clear, Enabled: true},

				{Name: "分类列表", Path: "categories", Method: "GET", Handler: m.handler.GetCategories, Enabled: true},
				{Name: "重载缓存", Path: "reload", Method: "POST", Handler: m.handler.Reload, Enabled: true},
			},
		},
	})
}
