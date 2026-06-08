package oplog

import (
	oplogContract "vulnscan-backend/circular/oplog/oplog-contract"

	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type HandlerOplog struct {
	svc oplogContract.ServiceOplog
}

func NewHandlerOplog(svc oplogContract.ServiceOplog) *HandlerOplog {
	return &HandlerOplog{svc: svc}
}

func (h *HandlerOplog) ByCircularId(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	logs, err := h.svc.ByCircularId(c.Request.Context(), uri.Id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(logs).Send()
}
