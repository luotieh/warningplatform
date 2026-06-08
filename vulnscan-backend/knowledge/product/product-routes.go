package product

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

type ProductRoutes struct {
	handler *HandlerProduct
}

func NewProductRoutes(handler *HandlerProduct) *ProductRoutes {
	return &ProductRoutes{handler: handler}
}

func (m *ProductRoutes) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/products"), []authorize.Route{
		{
			Name: "产品知识库", Enabled: true,
			Children: []authorize.Route{
				{Name: "产品列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "产品搜索", Path: "search", Method: "GET", Handler: m.handler.Search, Enabled: true},
				{Name: "产品详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "创建产品", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "更新产品", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除产品", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "回填关联", Path: "backfill", Method: "POST", Handler: m.handler.Backfill, Enabled: true},
				{Name: "分类统计", Path: "summary", Method: "GET", Handler: m.handler.Summary, Enabled: true},
				{Name: "重新分类", Path: "reclassify", Method: "POST", Handler: m.handler.Reclassify, Enabled: true},
			},
		},
	})
}
