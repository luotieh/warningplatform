package verify

import (
	inputContract "vulnscan-backend/circular/input/input-contract"
	verifyContract "vulnscan-backend/circular/verify/verify-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
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
	web.OK(c).List(total, items).Send()
}

func (h *HandlerVerify) Verify(c *gin.Context) {
	req, ok := web.BindJSON[verifyContract.VerifyReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.Verify(c.Request.Context(), req, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
