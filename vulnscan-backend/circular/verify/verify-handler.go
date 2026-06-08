package verify

import (
	inputContract "vulnscan-backend/circular/input/input-contract"
	"vulnscan-backend/circular/scope"
	verifyContract "vulnscan-backend/circular/verify/verify-contract"

	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type HandlerVerify struct {
	svc verifyContract.ServiceVerify
}

func NewHandlerVerify(svc verifyContract.ServiceVerify) *HandlerVerify {
	return &HandlerVerify{svc: svc}
}

func (h *HandlerVerify) List(c *gin.Context) {
	req, ok := web.BindQuery[inputContract.ListQuery](c)
	if !ok {
		return
	}
	total, items, err := h.svc.List(c, req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).List(total, items).Send()
}

func (h *HandlerVerify) Verify(c *gin.Context) {
	req, ok := web.BindJSON[verifyContract.VerifyReq](c)
	if !ok {
		return
	}
	if err := h.svc.Verify(c.Request.Context(), req, scope.ActorFromContext(c)); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}
