package payload

import (
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Routes struct {
	handler *Handler
}

func NewRoutes(handler *Handler) *Routes {
	return &Routes{handler: handler}
}

func (r *Routes) RegisterRoutes(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/payloads"), []authorize.Route{
		{
			Name: "Payload管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "Payload列表", Path: "list", Method: "GET", Handler: r.handler.ListPayloads, Enabled: true},
				{Name: "Payload详情", Path: ":id", Method: "GET", Handler: r.handler.GetPayloadByID, Enabled: true},
				{Name: "创建Payload", Path: "", Method: "POST", Handler: r.handler.CreatePayload, Enabled: true},
				{Name: "更新Payload", Path: ":id", Method: "PUT", Handler: r.handler.UpdatePayload, Enabled: true},
				{Name: "删除Payload", Path: ":id", Method: "DELETE", Handler: r.handler.DeletePayload, Enabled: true},
				{Name: "批量创建Payload", Path: "batch", Method: "POST", Handler: r.handler.BatchCreatePayloads, Enabled: true},
				{Name: "分类列表", Path: "categories", Method: "GET", Handler: r.handler.GetCategories, Enabled: true},

				{Name: "Pattern列表", Path: "patterns", Method: "GET", Handler: r.handler.ListPatterns, Enabled: true},
				{Name: "Pattern详情", Path: "patterns/:id", Method: "GET", Handler: r.handler.GetPatternByID, Enabled: true},
				{Name: "创建Pattern", Path: "patterns", Method: "POST", Handler: r.handler.CreatePattern, Enabled: true},
				{Name: "更新Pattern", Path: "patterns/:id", Method: "PUT", Handler: r.handler.UpdatePattern, Enabled: true},
				{Name: "删除Pattern", Path: "patterns/:id", Method: "DELETE", Handler: r.handler.DeletePattern, Enabled: true},
				{Name: "批量创建Pattern", Path: "patterns/batch", Method: "POST", Handler: r.handler.BatchCreatePatterns, Enabled: true},

				{Name: "Config列表", Path: "configs", Method: "GET", Handler: r.handler.ListConfigs, Enabled: true},
				{Name: "Config详情", Path: "configs/:id", Method: "GET", Handler: r.handler.GetConfigByID, Enabled: true},
				{Name: "创建Config", Path: "configs", Method: "POST", Handler: r.handler.CreateConfig, Enabled: true},
				{Name: "更新Config", Path: "configs/:id", Method: "PUT", Handler: r.handler.UpdateConfig, Enabled: true},
				{Name: "删除Config", Path: "configs/:id", Method: "DELETE", Handler: r.handler.DeleteConfig, Enabled: true},
			},
		},
	})
}
