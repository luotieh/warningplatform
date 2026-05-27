package assetmgr

import (
	"strconv"

	ac "vulnscan-backend/assetmgr/assetmgr-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"vulnscan-backend/pkg/definition"
)

type Handler struct {
	lifecycle   ac.ServiceLifecycle
	risk        ac.ServiceRisk
	alert       ac.ServiceAlert
	verify      ac.ServiceVerify
	verifyTask  ac.ServiceVerifyTask
	compliance  ac.ServiceComplianceItem
	tmpl        ac.ServiceComplianceTemplate
	check       ac.ServiceCheckResult
	responsible ac.ServiceResponsible
	integration ac.ServiceIntegration
	workflow    ac.ServiceWorkflow
}

func NewHandler(
	lifecycle ac.ServiceLifecycle,
	risk ac.ServiceRisk,
	alert ac.ServiceAlert,
	verify ac.ServiceVerify,
	verifyTask ac.ServiceVerifyTask,
	compliance ac.ServiceComplianceItem,
	tmpl ac.ServiceComplianceTemplate,
	check ac.ServiceCheckResult,
	responsible ac.ServiceResponsible,
	integration ac.ServiceIntegration,
	workflow ac.ServiceWorkflow,
) *Handler {
	return &Handler{
		lifecycle: lifecycle, risk: risk, alert: alert, verify: verify, verifyTask: verifyTask,
		compliance: compliance, tmpl: tmpl, check: check,
		responsible: responsible, integration: integration, workflow: workflow,
	}
}

// ── 生命周期 ──

func (h *Handler) LifecycleList(c *gin.Context) {
	req, _ := web.BindQuery[ac.LifecycleListReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.lifecycle.ListTransitions(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) LifecycleTransition(c *gin.Context) {
	var req ac.TransitionReq
	if !web.ValidationJson(c, &req) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.lifecycle.Transition(req.AssetID, req.ToState, user.UserID, req.Remark); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ── 风险评分 ──

func (h *Handler) RiskList(c *gin.Context) {
	req, _ := web.BindQuery[ac.RiskListReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.risk.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) RiskDetail(c *gin.Context) {
	item, err := h.risk.GetByAssetID(c.Param("asset_id"))
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) RiskRecalculate(c *gin.Context) {
	if err := h.risk.Recalculate(c.Param("asset_id")); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) RiskRecalculateAll(c *gin.Context) {
	count, err := h.risk.RecalculateAll()
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"recalculated": count}).Send()
}

// ── 告警 ──

func (h *Handler) AlertList(c *gin.Context) {
	req, _ := web.BindQuery[ac.AlertListReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.alert.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) AlertCreate(c *gin.Context) {
	var item model.Alert
	if !web.ValidationJson(c, &item) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item.CreatedBy = user.UserID
	if err := h.alert.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) AlertAck(c *gin.Context) {
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.alert.Ack(c.Param("id"), user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) AlertResolve(c *gin.Context) {
	if err := h.alert.Resolve(c.Param("id")); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ── 审核 ──

func (h *Handler) VerifyList(c *gin.Context) {
	req, _ := web.BindQuery[ac.VerifyListReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.verify.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) VerifySubmit(c *gin.Context) {
	var item model.AssetVerify
	if !web.ValidationJson(c, &item) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item.CreatedBy = user.UserID
	item.OrganizeID = user.OrganizeID
	if err := h.verify.Submit(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) VerifyReview(c *gin.Context) {
	var req ac.ReviewReq
	if !web.ValidationJson(c, &req) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.verify.Review(c.Param("id"), req.ReviewStatus, req.ReviewRemark, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ── 合规项 ──

func (h *Handler) VerifyTaskList(c *gin.Context) {
	req, ok := web.BindQuery[ac.VerifyTaskListReq](c)
	if !ok {
		return
	}
	scope := iamsdk.DataFilterScope(c, definition.VerifyTaskFieldMapping)
	items, count, err := h.verifyTask.ListTasks(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) VerifyTaskCreate(c *gin.Context) {
	req, ok := web.BindJSON[ac.VerifyTaskCreateReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	items, err := h.verifyTask.CreateTasks(req, user.UserID, user.OrganizeID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"items": items, "count": len(items)}).Send()
}

func (h *Handler) VerifyTaskDelete(c *gin.Context) {
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.verifyTask.Delete(c.Param("id"), user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) VerifyTaskReceive(c *gin.Context) {
	req, ok := web.BindJSON[ac.VerifyTaskActionReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.verifyTask.Receive(c.Param("id"), user.UserID, user.OrganizeID, req.Remark); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) VerifyTaskConfirm(c *gin.Context) {
	req, ok := web.BindJSON[ac.VerifyTaskActionReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.verifyTask.Confirm(c.Param("id"), user.UserID, req.Remark); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) VerifyTaskReject(c *gin.Context) {
	req, ok := web.BindJSON[ac.VerifyTaskActionReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.verifyTask.Reject(c.Param("id"), user.UserID, req.RejectReason, req.Remark); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) VerifyTaskForward(c *gin.Context) {
	req, ok := web.BindJSON[ac.VerifyTaskActionReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.verifyTask.Forward(c.Param("id"), req.TargetOrganizeID, user.UserID, req.Remark); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) VerifyTaskReturn(c *gin.Context) {
	req, ok := web.BindJSON[ac.VerifyTaskActionReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.verifyTask.Return(c.Param("id"), user.UserID, req.Remark); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) VerifyTaskArchive(c *gin.Context) {
	req, ok := web.BindJSON[ac.VerifyTaskActionReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.verifyTask.Archive(c.Param("id"), user.UserID, req.Remark); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) VerifyTaskReactivate(c *gin.Context) {
	req, ok := web.BindJSON[ac.VerifyTaskActionReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.verifyTask.Reactivate(c.Param("id"), user.UserID, req.Remark); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) VerifyTaskLogs(c *gin.Context) {
	req, ok := web.BindQuery[ac.VerifyTaskLogsReq](c)
	if !ok {
		return
	}
	if req.TaskID == "" {
		req.TaskID = c.Param("id")
	}
	items, count, err := h.verifyTask.ListLogs(req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) ArchiveList(c *gin.Context) {
	req, ok := web.BindQuery[ac.ArchiveListReq](c)
	if !ok {
		return
	}
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.verifyTask.ListArchives(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) ArchiveDetail(c *gin.Context) {
	item, err := h.verifyTask.GetArchive(c.Param("id"))
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) ComplianceList(c *gin.Context) {
	req, _ := web.BindQuery[ac.ComplianceItemReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.compliance.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) ComplianceCreate(c *gin.Context) {
	var item model.AssetCompliance
	if !web.ValidationJson(c, &item) {
		return
	}
	if err := h.compliance.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) ComplianceUpdate(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	body, ok := web.BindJSON[map[string]interface{}](c)
	if !ok {
		return
	}
	if err := h.compliance.Update(id, body); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) ComplianceDelete(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := h.compliance.Delete(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ── 责任人 ──

func (h *Handler) ResponsibleList(c *gin.Context) {
	req, _ := web.BindQuery[ac.ResponsibleListReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.responsible.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) ResponsibleCreate(c *gin.Context) {
	var item model.AssetResponsible
	if !web.ValidationJson(c, &item) {
		return
	}
	if err := h.responsible.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) ResponsibleUpdate(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	body, ok := web.BindJSON[map[string]interface{}](c)
	if !ok {
		return
	}
	if err := h.responsible.Update(id, body); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) ResponsibleDelete(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := h.responsible.Delete(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ── 合规模板 ──

func (h *Handler) TemplateList(c *gin.Context) {
	req, _ := web.BindQuery[ac.TemplateListReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.tmpl.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) TemplateDetail(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	item, err := h.tmpl.GetByID(id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	tmplItems, _ := h.tmpl.ListItems(id)
	web.OK(c).Data(gin.H{"template": item, "items": tmplItems}).Send()
}

func (h *Handler) TemplateCreate(c *gin.Context) {
	var item model.ComplianceTemplate
	if !web.ValidationJson(c, &item) {
		return
	}
	if err := h.tmpl.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) TemplateItemCreate(c *gin.Context) {
	var item model.ComplianceTemplateItem
	if !web.ValidationJson(c, &item) {
		return
	}
	if err := h.tmpl.CreateItem(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

// ── 合规检查结果 ──

func (h *Handler) CheckResultList(c *gin.Context) {
	req, _ := web.BindQuery[ac.CheckResultListReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.check.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) CheckResultUpsert(c *gin.Context) {
	var item model.ComplianceCheckResult
	if !web.ValidationJson(c, &item) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item.CheckedBy = user.UserID
	if err := h.check.Upsert(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ── 集成数据源 ──

func (h *Handler) IntSourceList(c *gin.Context) {
	req, _ := web.BindQuery[ac.IntSourceListReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.integration.ListSources(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) IntSourceCreate(c *gin.Context) {
	var item model.IntegrationSource
	if !web.ValidationJson(c, &item) {
		return
	}
	if err := h.integration.CreateSource(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) IntSourceUpdate(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	body, ok := web.BindJSON[map[string]interface{}](c)
	if !ok {
		return
	}
	if err := h.integration.UpdateSource(id, body); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) IntSourceDelete(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := h.integration.DeleteSource(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ── 工作流 ──

func (h *Handler) WorkflowList(c *gin.Context) {
	req, _ := web.BindQuery[ac.WorkflowListReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.workflow.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) WorkflowCreate(c *gin.Context) {
	var item model.Workflow
	if !web.ValidationJson(c, &item) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item.CreatedBy = user.UserID
	item.ID = qulid.GenerateID()
	if err := h.workflow.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) WorkflowUpdate(c *gin.Context) {
	id := c.Param("id")
	body, ok := web.BindJSON[map[string]interface{}](c)
	if !ok {
		return
	}
	if err := h.workflow.Update(id, body); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) WorkflowDelete(c *gin.Context) {
	if err := h.workflow.Delete(c.Param("id")); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) WorkflowExecutions(c *gin.Context) {
	req, _ := web.BindQuery[ac.ExecutionListReq](c)
	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.workflow.ListExecutions(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}
