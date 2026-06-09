package task

import (
	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

type Task struct {
	handler *HandlerTask
}

func NewTask(handler *HandlerTask) *Task {
	return &Task{handler: handler}
}

func (m *Task) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/task"), []authorize.Route{
		{
			Name: "扫描任务", Enabled: true,
			Children: []authorize.Route{
				{Name: "任务列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "任务详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
				{Name: "创建任务", Method: "POST", Handler: m.handler.Create, Enabled: true},
				{Name: "删除任务", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
				{Name: "取消任务", Path: ":id/cancel", Method: "POST", Handler: m.handler.Cancel, Enabled: true},
				{Name: "暂停任务", Path: ":id/pause", Method: "POST", Handler: m.handler.Pause, Enabled: true},
				{Name: "恢复任务", Path: ":id/resume", Method: "POST", Handler: m.handler.Resume, Enabled: true},
				{Name: "任务发现列表", Path: ":id/findings", Method: "GET", Handler: m.handler.ListFindings, Enabled: true},
				{Name: "任务发现摘要", Path: ":id/findings/summary", Method: "GET", Handler: m.handler.FindingSummary, Enabled: true},
				{Name: "任务资产视图", Path: ":id/assets", Method: "GET", Handler: m.handler.ListAssets, Enabled: true},
				{Name: "任务运行日志", Path: ":id/logs", Method: "GET", Handler: m.handler.ListLogs, Enabled: true},
				{Name: "AI补充漏洞信息", Path: ":id/findings/:findingId/ai-enrich", Method: "POST", Handler: m.handler.AIEnrichFinding, Enabled: true},
				{Name: "漏洞知识列表", Path: "vuln-knowledge", Method: "GET", Handler: m.handler.ListVulnKnowledge, Enabled: true},
				{Name: "编辑漏洞知识", Path: "vuln-knowledge/:id", Method: "PUT", Handler: m.handler.UpdateVulnKnowledge, Enabled: true},
				{Name: "删除漏洞知识", Path: "vuln-knowledge/:id", Method: "DELETE", Handler: m.handler.DeleteVulnKnowledge, Enabled: true},
			},
		},
	})
}
