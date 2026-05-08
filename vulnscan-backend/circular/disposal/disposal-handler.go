package disposal

import (
	disposalContract "vulnscan-backend/circular/disposal/disposal-contract"
	distributeContract "vulnscan-backend/circular/distribute/distribute-contract"
	inputContract "vulnscan-backend/circular/input/input-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

type HandlerDisposal struct {
	svc disposalContract.ServiceDisposal
}

func NewHandlerDisposal(svc disposalContract.ServiceDisposal) *HandlerDisposal {
	return &HandlerDisposal{svc: svc}
}

func (h *HandlerDisposal) List(c *gin.Context) {
	req, ok := web.BindQuery[inputContract.ListQuery](c)
	if !ok {
		return
	}
	total, items, err := h.svc.List(c, req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, items).Send()
}

func (h *HandlerDisposal) Dispose(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[disposalContract.DisposalCondition](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.Dispose(c, uri.Id, user.UserID, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerDisposal) Redistribute(c *gin.Context) {
	req, ok := web.BindJSON[distributeContract.RedistributeReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.Redistribute(c, req, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
