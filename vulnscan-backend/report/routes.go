package report

import (
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type Report struct {
	handler *Handler
}

func NewReport(handler *Handler) *Report {
	return &Report{handler: handler}
}

func (m *Report) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/report"), []authorize.Route{
		{Name: "报告中心", Enabled: true, Children: []authorize.Route{
			{Name: "生成报告", Path: "generate", Method: "POST", Handler: m.handler.Generate, Enabled: true},
			{Name: "预览报告", Path: "preview", Method: "POST", Handler: m.handler.Preview, Enabled: true},
			{Name: "任务报告", Path: "task/:task_id", Method: "GET", Handler: m.handler.TaskReport, Enabled: true},
			{Name: "任务对比", Path: "compare", Method: "GET", Handler: m.handler.Compare, Enabled: true},
			{Name: "可用任务", Path: "tasks", Method: "GET", Handler: m.handler.AvailableTasks, Enabled: true},
		}},
	})
}
