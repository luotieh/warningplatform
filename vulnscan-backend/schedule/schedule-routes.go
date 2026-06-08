package schedule

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

type Schedule struct {
	handler *Handler
}

func NewSchedule(handler *Handler) *Schedule {
	return &Schedule{handler: handler}
}

func (m *Schedule) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/schedule"), []authorize.Route{
		{
			Name: "定时调度", Enabled: true,
			Children: []authorize.Route{
				{Name: "调度列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "调度详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "创建调度", Path: "", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "更新调度", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
				{Name: "删除调度", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "启停调度", Path: ":id/toggle", Method: "POST", Handler: m.handler.Toggle, Enabled: true},
				{Name: "立即执行", Path: ":id/run", Method: "POST", Handler: m.handler.RunNow, Enabled: true},
			},
		},
	})
}
