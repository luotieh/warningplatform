package prompt

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

type Prompt struct {
	handler *Handler
}

func NewPrompt(handler *Handler) *Prompt {
	return &Prompt{handler: handler}
}

func (m *Prompt) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/prompt-templates"), []authorize.Route{
		{
			Name: "提示模板", Enabled: true,
			Children: []authorize.Route{
				{Name: "模板列表", Path: "", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "模板详情", Path: ":id", Method: "GET", Handler: m.handler.Detail, Enabled: true},
				{Name: "按场景获取", Path: "by-scene", Method: "GET", Handler: m.handler.GetByScene, Enabled: true},
				{Name: "创建模板", Path: "", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "更新模板", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除模板", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "启停模板", Path: ":id/toggle", Method: "POST", Handler: m.handler.Toggle, Enabled: true},
			},
		},
	})
}
