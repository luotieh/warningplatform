package dispatch

import (
	dispatchContract "vulnscan-backend/dispatch/dispatch-contract"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type ContactHandler struct {
	svc dispatchContract.ServiceContact
}

func NewContactHandler(svc dispatchContract.ServiceContact) *ContactHandler {
	return &ContactHandler{svc: svc}
}

func (h *ContactHandler) List(c *gin.Context) {
	q, ok := web.BindQuery[dispatchContract.ContactQuery](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	items, total, err := h.svc.List(c.Request.Context(), q, user.OrganizeID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).List(total, items).Send()
}

func (h *ContactHandler) Detail(c *gin.Context) {
	id := c.Param("id")
	contact, err := h.svc.GetByID(c.Request.Context(), id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(contact).Send()
}

func (h *ContactHandler) Create(c *gin.Context) {
	req, ok := web.BindJSON[dispatchContract.CreateContactReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	contact, err := h.svc.Create(c.Request.Context(), req, user.UserID, user.OrganizeID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(contact).Send()
}

func (h *ContactHandler) Update(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[dispatchContract.UpdateContactReq](c)
	if !ok {
		return
	}
	if err := h.svc.Update(c.Request.Context(), id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *ContactHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}
