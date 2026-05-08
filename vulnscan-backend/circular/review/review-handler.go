package review

import (
	inputContract "vulnscan-backend/circular/input/input-contract"
	reviewContract "vulnscan-backend/circular/review/review-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
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
	web.OK(c).List(total, items).Send()
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
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.Review(c, uri.Id, user.UserID, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
