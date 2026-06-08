package compliance

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

type Compliance struct {
	handler *Handler
}

func NewCompliance(handler *Handler) *Compliance {
	return &Compliance{handler: handler}
}

func (m *Compliance) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/compliance"), []authorize.Route{
		{Name: "合规检查", Enabled: true, Children: []authorize.Route{
			{Name: "基线列表", Path: "frameworks", Method: "GET", Handler: m.handler.ListFrameworks, Enabled: true},
			{Name: "基线详情", Path: "frameworks/:id", Method: "GET", Handler: m.handler.GetFramework, Enabled: true},
			{Name: "基线规则", Path: "frameworks/:id/rules", Method: "GET", Handler: m.handler.GetRules, Enabled: true},
			{Name: "执行检查", Path: "check", Method: "POST", Handler: m.handler.RunCheck, Enabled: true},
		}},
	})
}
