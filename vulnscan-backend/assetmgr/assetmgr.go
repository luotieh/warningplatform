// Package assetmgr 资产治理：生命周期、合规、核查、告警、责任人、工作流。
package assetmgr

import (
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
)

type AssetMgr struct {
	handler *Handler
}

func NewAssetMgr(handler *Handler) *AssetMgr {
	return &AssetMgr{handler: handler}
}

func (m *AssetMgr) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/assetmgr"), []authorize.Route{
		{
			Name: "生命周期", Path: "lifecycle", Enabled: true,
			Children: []authorize.Route{
				{Name: "变更记录", Path: "list", Method: "GET", Handler: m.handler.LifecycleList, Enabled: true},
				{Name: "状态变更", Path: "transition", Method: "POST", Handler: m.handler.LifecycleTransition, Enabled: true},
			},
		},
		{
			Name: "风险评估", Path: "risk", Enabled: true,
			Children: []authorize.Route{
				{Name: "风险列表", Path: "list", Method: "GET", Handler: m.handler.RiskList, Enabled: true},
				{Name: "资产风险", Path: ":asset_id", Method: "GET", Handler: m.handler.RiskDetail, Enabled: true},
				{Name: "重算风险", Path: ":asset_id/recalculate", Method: "POST", Handler: m.handler.RiskRecalculate, Enabled: true},
				{Name: "全部重算", Path: "recalculate-all", Method: "POST", Handler: m.handler.RiskRecalculateAll, Enabled: true},
			},
		},
		{
			Name: "安全告警", Path: "alert", Enabled: true,
			Children: []authorize.Route{
				{Name: "告警列表", Path: "list", Method: "GET", Handler: m.handler.AlertList, Enabled: true},
				{Name: "创建告警", Method: "POST", Handler: m.handler.AlertCreate, Enabled: true},
				{Name: "确认告警", Path: ":id/ack", Method: "PUT", Handler: m.handler.AlertAck, Enabled: true},
				{Name: "解决告警", Path: ":id/resolve", Method: "PUT", Handler: m.handler.AlertResolve, Enabled: true},
			},
		},
		{
			Name: "资产审核", Path: "verify", Enabled: true,
			Children: []authorize.Route{
				{Name: "审核列表", Path: "list", Method: "GET", Handler: m.handler.VerifyList, Enabled: true},
				{Name: "提交审核", Method: "POST", Handler: m.handler.VerifySubmit, Enabled: true},
				{Name: "审批", Path: ":id/review", Method: "PUT", Handler: m.handler.VerifyReview, Enabled: true},
				{Name: "核验任务列表", Path: "tasks/list", Method: "GET", Handler: m.handler.VerifyTaskList, Enabled: true},
				{Name: "创建核验任务", Path: "tasks", Method: "POST", Handler: m.handler.VerifyTaskCreate, Enabled: true},
				{Name: "接收核验任务", Path: "tasks/:id/receive", Method: "PUT", Handler: m.handler.VerifyTaskReceive, Enabled: true},
				{Name: "确认核验任务", Path: "tasks/:id/confirm", Method: "PUT", Handler: m.handler.VerifyTaskConfirm, Enabled: true},
				{Name: "驳回核验任务", Path: "tasks/:id/reject", Method: "PUT", Handler: m.handler.VerifyTaskReject, Enabled: true},
				{Name: "转发核验任务", Path: "tasks/:id/forward", Method: "PUT", Handler: m.handler.VerifyTaskForward, Enabled: true},
				{Name: "退回核验任务", Path: "tasks/:id/return", Method: "PUT", Handler: m.handler.VerifyTaskReturn, Enabled: true},
				{Name: "归档核验任务", Path: "tasks/:id/archive", Method: "PUT", Handler: m.handler.VerifyTaskArchive, Enabled: true},
				{Name: "重新激活核验任务", Path: "tasks/:id/reactivate", Method: "PUT", Handler: m.handler.VerifyTaskReactivate, Enabled: true},
				{Name: "核验流转日志", Path: "tasks/:id/logs", Method: "GET", Handler: m.handler.VerifyTaskLogs, Enabled: true},
			},
		},
		{
			Name: "资产归档", Path: "archive", Enabled: true,
			Children: []authorize.Route{
				{Name: "归档资产列表", Path: "assets/list", Method: "GET", Handler: m.handler.ArchiveList, Enabled: true},
				{Name: "归档资产详情", Path: "assets/:id", Method: "GET", Handler: m.handler.ArchiveDetail, Enabled: true},
			},
		},
		{
			Name: "合规管理", Path: "compliance", Enabled: true,
			Children: []authorize.Route{
				{Name: "合规项列表", Path: "items/list", Method: "GET", Handler: m.handler.ComplianceList, Enabled: true},
				{Name: "创建合规项", Path: "items", Method: "POST", Handler: m.handler.ComplianceCreate, Enabled: true},
				{Name: "更新合规项", Path: "items/:id", Method: "PUT", Handler: m.handler.ComplianceUpdate, Enabled: true},
				{Name: "删除合规项", Path: "items/:id", Method: "DELETE", Handler: m.handler.ComplianceDelete, Enabled: true},
				{Name: "模板列表", Path: "templates/list", Method: "GET", Handler: m.handler.TemplateList, Enabled: true},
				{Name: "模板详情", Path: "templates/:id", Method: "GET", Handler: m.handler.TemplateDetail, Enabled: true},
				{Name: "创建模板", Path: "templates", Method: "POST", Handler: m.handler.TemplateCreate, Enabled: true},
				{Name: "创建检查项", Path: "templates/items", Method: "POST", Handler: m.handler.TemplateItemCreate, Enabled: true},
				{Name: "检查结果列表", Path: "results/list", Method: "GET", Handler: m.handler.CheckResultList, Enabled: true},
				{Name: "提交检查结果", Path: "results", Method: "POST", Handler: m.handler.CheckResultUpsert, Enabled: true},
			},
		},
		{
			Name: "责任人", Path: "responsible", Enabled: true,
			Children: []authorize.Route{
				{Name: "责任人列表", Path: "list", Method: "GET", Handler: m.handler.ResponsibleList, Enabled: true},
				{Name: "添加责任人", Method: "POST", Handler: m.handler.ResponsibleCreate, Enabled: true},
				{Name: "更新责任人", Path: ":id", Method: "PUT", Handler: m.handler.ResponsibleUpdate, Enabled: true},
				{Name: "删除责任人", Path: ":id", Method: "DELETE", Handler: m.handler.ResponsibleDelete, Enabled: true},
			},
		},
		{
			Name: "数据集成", Path: "integration", Enabled: true,
			Children: []authorize.Route{
				{Name: "数据源列表", Path: "sources/list", Method: "GET", Handler: m.handler.IntSourceList, Enabled: true},
				{Name: "创建数据源", Path: "sources", Method: "POST", Handler: m.handler.IntSourceCreate, Enabled: true},
				{Name: "更新数据源", Path: "sources/:id", Method: "PUT", Handler: m.handler.IntSourceUpdate, Enabled: true},
				{Name: "删除数据源", Path: "sources/:id", Method: "DELETE", Handler: m.handler.IntSourceDelete, Enabled: true},
			},
		},
		{
			Name: "自动化工作流", Path: "workflow", Enabled: true,
			Children: []authorize.Route{
				{Name: "工作流列表", Path: "list", Method: "GET", Handler: m.handler.WorkflowList, Enabled: true},
				{Name: "创建工作流", Method: "POST", Handler: m.handler.WorkflowCreate, Enabled: true},
				{Name: "更新工作流", Path: ":id", Method: "PUT", Handler: m.handler.WorkflowUpdate, Enabled: true},
				{Name: "删除工作流", Path: ":id", Method: "DELETE", Handler: m.handler.WorkflowDelete, Enabled: true},
				{Name: "执行记录", Path: "executions", Method: "GET", Handler: m.handler.WorkflowExecutions, Enabled: true},
			},
		},
	})
}
