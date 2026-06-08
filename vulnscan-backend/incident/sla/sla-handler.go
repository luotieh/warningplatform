package sla

import (
	slaContract "vulnscan-backend/incident/sla/sla-contract"

	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type HandlerSLA struct {
	svc slaContract.ServiceSLA
}

func NewHandlerSLA(svc slaContract.ServiceSLA) *HandlerSLA {
	return &HandlerSLA{svc: svc}
}

func (h *HandlerSLA) SLAOverview(c *gin.Context) {
	resp, err := h.svc.GetSLAOverview(c)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(resp).Send()
}

func (h *HandlerSLA) SetSLA(c *gin.Context) {
	req, ok := web.BindJSON[slaContract.SLASetReq](c)
	if !ok {
		return
	}
	if err := h.svc.SetSLA(c, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerSLA) CheckSLA(c *gin.Context) {
	result, err := h.svc.CheckAndUpdateSLA(c)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(result).Send()
}
