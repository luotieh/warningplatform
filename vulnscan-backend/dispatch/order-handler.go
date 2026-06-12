package dispatch

import (
	dispatchContract "vulnscan-backend/dispatch/dispatch-contract"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type OrderHandler struct {
	svc dispatchContract.ServiceOrder
}

func NewOrderHandler(svc dispatchContract.ServiceOrder) *OrderHandler {
	return &OrderHandler{svc: svc}
}

func (h *OrderHandler) List(c *gin.Context) {
	q, ok := web.BindQuery[dispatchContract.OrderQuery](c)
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

func (h *OrderHandler) Detail(c *gin.Context) {
	id := c.Param("id")
	order, err := h.svc.GetByID(c.Request.Context(), id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(order).Send()
}

func (h *OrderHandler) Create(c *gin.Context) {
	req, ok := web.BindJSON[dispatchContract.CreateOrderReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	order, err := h.svc.Create(c.Request.Context(), req, user.UserID, user.OrganizeID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(order).Send()
}

func (h *OrderHandler) Cancel(c *gin.Context) {
	id := c.Param("id")
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.Cancel(c.Request.Context(), id, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *OrderHandler) Assign(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[dispatchContract.AssignReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.Assign(c.Request.Context(), id, req, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *OrderHandler) Accept(c *gin.Context) {
	id := c.Param("id")
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.Accept(c.Request.Context(), id, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *OrderHandler) Reject(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.Reject(c.Request.Context(), id, user.UserID, body.Reason); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *OrderHandler) SubmitResult(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[dispatchContract.SubmitResultReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.SubmitResult(c.Request.Context(), id, req, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *OrderHandler) Review(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[dispatchContract.ReviewReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if err := h.svc.Review(c.Request.Context(), id, req, user.UserID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *OrderHandler) Oplogs(c *gin.Context) {
	id := c.Param("id")
	logs, err := h.svc.GetOplogs(c.Request.Context(), id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(logs).Send()
}

func (h *OrderHandler) Stats(c *gin.Context) {
	user, _ := iamsdk.GetCurrentUser(c)
	stats, err := h.svc.Stats(c.Request.Context(), user.OrganizeID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(stats).Send()
}
