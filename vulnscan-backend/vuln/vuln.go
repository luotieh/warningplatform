package vuln

import (
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Vuln struct {
	handler *HandlerVuln
}

func NewVuln(handler *HandlerVuln) *Vuln {
	return &Vuln{handler: handler}
}

func (m *Vuln) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/vuln"), []authorize.Route{
		{
			Name: "漏洞管理", Enabled: true,
			Children: []authorize.Route{
				{Name: "漏洞列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "漏洞统计", Path: "stats", Method: "GET", Handler: m.handler.Stats, Enabled: true},
				{Name: "漏洞详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "删除漏洞", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "标记已修复", Path: ":id/fix", Method: "POST", Handler: m.handler.MarkFixed, Enabled: true},
				{Name: "标记忽略", Path: ":id/ignore", Method: "POST", Handler: m.handler.MarkIgnored, Enabled: true},
				{Name: "重新打开", Path: ":id/reopen", Method: "POST", Handler: m.handler.Reopen, Enabled: true},
				{Name: "状态历史", Path: ":id/history", Method: "GET", Handler: m.handler.StatusHistory, Enabled: true},
			},
		},
	})
}
