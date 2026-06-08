package review

import (
	inputContract "vulnscan-backend/circular/input/input-contract"
	reviewContract "vulnscan-backend/circular/review/review-contract"
	"vulnscan-backend/circular/scope"

	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type HandlerReview struct {
	svc reviewContract.ServiceReview
}

func NewHandlerReview(svc reviewContract.ServiceReview) *HandlerReview {
	return &HandlerReview{svc: svc}
}

func (h *HandlerReview) List(c *gin.Context) {
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

func (h *HandlerReview) Review(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[reviewContract.ReviewCondition](c)
	if !ok {
		return
	}
	if err := h.svc.Review(c, uri.Id, scope.ActorFromContext(c), req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}
