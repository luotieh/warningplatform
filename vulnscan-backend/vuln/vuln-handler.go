package vuln

import (
	"errors"

	"vulnscan-backend/scanrunner"
	vulnContract "vulnscan-backend/vuln/vuln-contract"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"vulnscan-backend/pkg/definition"
)

type HandlerVuln struct {
	svc       vulnContract.ServiceVuln
	scanDB    *gorm.DB
	scanSched *scanrunner.Scheduler
}

func NewHandlerVuln(svc vulnContract.ServiceVuln) *HandlerVuln {
	return &HandlerVuln{svc: svc}
}

func (h *HandlerVuln) BindScanRunner(session *gorm.DB, sched *scanrunner.Scheduler) {
	h.scanDB = session
	h.scanSched = sched
}

func (h *HandlerVuln) List(c *gin.Context) {
	query, ok := web.BindQuery[vulnContract.VulnQuery](c)
	if !ok {
		return
	}

	scope := definition.SafeDataFilterScope(c, definition.VulnscanFieldMapping)
	items, count, err := h.svc.List(query, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).List(count, items).Send()
}

func (h *HandlerVuln) GetByID(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}

	item, err := h.svc.GetByID(uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(item).Send()
}

func (h *HandlerVuln) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}

	if err := h.svc.Delete(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

type markIgnoredReq struct {
	Reason string `json:"reason"`
}

func (h *HandlerVuln) MarkFixed(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.MarkFixed(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerVuln) MarkIgnored(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[markIgnoredReq](c)
	if !ok {
		return
	}
	if err := h.svc.MarkIgnored(uri.Id, req.Reason); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerVuln) Reopen(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Reopen(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerVuln) StatusHistory(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	items, err := h.svc.GetStatusHistory(uri.Id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(items).Send()
}

func (h *HandlerVuln) Retest(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if h.scanDB == nil || h.scanSched == nil {
		web.Fail(c).Msg("扫描调度器未初始化").Send()
		return
	}
	vuln, err := h.svc.GetByID(uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	res, err := scanrunner.LaunchVulnRetest(h.scanDB, h.scanSched, vuln, user.UserID, user.OrganizeID)
	if errors.Is(err, scanrunner.ErrTemplateNotFound) {
		web.Fail(c).Msg("回测模板不存在，请重启服务同步内置模板").Send()
		return
	}
	if err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}
	web.Succeed(c).Data(map[string]any{
		"task_id":  res.Task.ID,
		"status":   res.Task.Status,
		"vuln_id":  vuln.ID,
		"template": res.Task.TemplateName,
	}).Send()
}

func (h *HandlerVuln) RetestFromFinding(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if h.scanDB == nil || h.scanSched == nil {
		web.Fail(c).Msg("扫描调度器未初始化").Send()
		return
	}
	vulnID, err := scanrunner.EnsureVulnFromFinding(h.scanDB, uri.Id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	vuln, err := h.svc.GetByID(vulnID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	res, err := scanrunner.LaunchVulnRetest(h.scanDB, h.scanSched, vuln, user.UserID, user.OrganizeID)
	if errors.Is(err, scanrunner.ErrTemplateNotFound) {
		web.Fail(c).Msg("回测模板不存在，请重启服务同步内置模板").Send()
		return
	}
	if err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}
	web.Succeed(c).Data(map[string]any{
		"task_id":    res.Task.ID,
		"status":     res.Task.Status,
		"vuln_id":    vuln.ID,
		"finding_id": uri.Id,
	}).Send()
}

func (h *HandlerVuln) Stats(c *gin.Context) {
	scope := definition.SafeDataFilterScope(c, definition.VulnscanFieldMapping)
	stats, err := h.svc.Stats(scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(stats).Send()
}
