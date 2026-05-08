package audit

import (
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
	req, ok := web.BindJSON[struct {
		ID string `json:"id" binding:"required"`
	}](c)
	if !ok {
		return
	}
	result, err := h.svc.AIPreAudit(c, req.ID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(result).Send()
}

func (h *HandlerAudit) ManualAudit(c *gin.Context) {
	req, ok := web.BindJSON[auditContract.ManualAuditReq](c)
	if !ok {
		return
	}
	if err := h.svc.ManualAudit(c, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerAudit) AIClassify(c *gin.Context) {
	req, ok := web.BindJSON[struct {
		ID string `json:"id" binding:"required"`
	}](c)
	if !ok {
		return
	}
	result, err := h.svc.AIClassify(c, req.ID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(result).Send()
}
