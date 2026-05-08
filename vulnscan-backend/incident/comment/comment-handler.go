package comment

import (
	commentContract "vulnscan-backend/incident/comment/comment-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

type HandlerComment struct {
	svc commentContract.ServiceComment
}

func NewHandlerComment(svc commentContract.ServiceComment) *HandlerComment {
	return &HandlerComment{svc: svc}
}

func (h *HandlerComment) CreateComment(c *gin.Context) {
	req, ok := web.BindJSON[commentContract.CommentCreateReq](c)
	if !ok {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	req.AuthorId = user.UserID
	req.AuthorName = user.Account

	item, err := h.svc.CreateComment(c, req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerComment) ListComments(c *gin.Context) {
	query, ok := web.BindQuery[struct {
		IncidentId string `form:"incident_id" binding:"required"`
	}](c)
	if !ok {
		return
	}

	items, err := h.svc.ListComments(c, query.IncidentId)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(items).Send()
}

func (h *HandlerComment) DeleteComment(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.DeleteComment(c, uri.Id, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
