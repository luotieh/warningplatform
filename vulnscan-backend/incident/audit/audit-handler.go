package audit

import (
	"io"

	auditContract "vulnscan-backend/incident/audit/audit-contract"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type HandlerAudit struct {
	svc auditContract.ServiceAudit
}

func NewHandlerAudit(svc auditContract.ServiceAudit) *HandlerAudit {
	return &HandlerAudit{svc: svc}
}

func (h *HandlerAudit) AIPreAudit(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	result, err := h.svc.AIPreAudit(c, uri.Id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(result).Send()
}

func (h *HandlerAudit) ManualAudit(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	body, ok := bindManualAuditBody(c)
	if !ok {
		return
	}
	req := auditContract.ManualAuditReq{
		ID:          uri.Id,
		AuditResult: body.AuditResult,
		Opinion:     body.Opinion,
	}
	if err := h.svc.ManualAudit(c, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func bindManualAuditBody(c *gin.Context) (auditContract.ManualAuditBody, bool) {
	var body auditContract.ManualAuditBody
	if err := c.ShouldBindJSON(&body); err != nil {
		if err == io.EOF {
			web.Err(c, web.ParamsMissingRequired).Send()
			return body, false
		}
		web.Fail(c).Err(err).Send()
		return body, false
	}
	if body.AuditResult == "" && body.Passed != nil {
		if *body.Passed {
			body.AuditResult = "success"
		} else {
			body.AuditResult = "fail"
		}
	}
	if body.AuditResult != "success" && body.AuditResult != "fail" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return body, false
	}
	return body, true
}

func (h *HandlerAudit) AIClassify(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	result, err := h.svc.AIClassify(c, uri.Id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(result).Send()
}
