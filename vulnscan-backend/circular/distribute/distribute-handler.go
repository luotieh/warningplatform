package distribute

import (
	distributeContract "vulnscan-backend/circular/distribute/distribute-contract"
	inputContract "vulnscan-backend/circular/input/input-contract"
	"vulnscan-backend/circular/scope"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type HandlerDistribute struct {
	svc distributeContract.ServiceDistribute
}

func NewHandlerDistribute(svc distributeContract.ServiceDistribute) *HandlerDistribute {
	return &HandlerDistribute{svc: svc}
}

func (h *HandlerDistribute) List(c *gin.Context) {
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

func (h *HandlerDistribute) Distribute(c *gin.Context) {
	req, ok := web.BindJSON[distributeContract.DistributeReq](c)
	if !ok {
		return
	}
	if err := h.svc.Distribute(c, req, scope.ActorFromContext(c)); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
