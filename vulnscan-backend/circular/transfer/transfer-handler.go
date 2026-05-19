package transfer

import (
	"vulnscan-backend/circular/scope"
	transferContract "vulnscan-backend/circular/transfer/transfer-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

type HandlerTransfer struct {
	svc transferContract.ServiceTransfer
}

func NewHandlerTransfer(svc transferContract.ServiceTransfer) *HandlerTransfer {
	return &HandlerTransfer{svc: svc}
}

func (h *HandlerTransfer) TransferService() transferContract.ServiceTransfer {
	return h.svc
}

func (h *HandlerTransfer) ReceiveIncident(c *gin.Context) {
	req, ok := web.BindJSON[transferContract.TransferIncidentReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	code, err := h.svc.ReceiveIncident(c.Request.Context(), req, scope.ActorFromContext(c), user.OrganizeID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(map[string]string{"circular_code": code}).Send()
}

func (h *HandlerTransfer) ReceiveIncidentBatch(c *gin.Context) {
	req, ok := web.BindJSON[transferContract.TransferIncidentBatchReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	results, err := h.svc.ReceiveIncidentBatch(c.Request.Context(), req, scope.ActorFromContext(c), user.OrganizeID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(results).Send()
}

func (h *HandlerTransfer) GetTransferStatus(c *gin.Context) {
	req, ok := web.BindQuery[struct {
		IncidentNo string `form:"incident_no" binding:"required"`
	}](c)
	if !ok {
		return
	}
	resp, err := h.svc.GetTransferStatus(c.Request.Context(), req.IncidentNo)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(resp).Send()
}
