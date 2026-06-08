package notify

import (
	"code.yt-security.com/public/access/authorize"
	"code.yt-security.com/public/access/middleware"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *ServiceNotify
}

func NewHandler(svc *ServiceNotify) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) List(c *gin.Context) {
	user, _ := middleware.GetCurrentUser(c)
	userID := ""
	if user != nil {
		userID = user.UserID
	}

	readFilter := c.DefaultQuery("read", "")
	notifyType := c.Query("type")

	items, count := h.svc.List(userID, readFilter, notifyType)
	web.Succeed(c).List(count, items).Send()
}

func (h *Handler) UnreadCount(c *gin.Context) {
	user, _ := middleware.GetCurrentUser(c)
	userID := ""
	if user != nil {
		userID = user.UserID
	}

	count := h.svc.UnreadCount(userID)
	web.Succeed(c).Data(gin.H{"count": count}).Send()
}

func (h *Handler) MarkRead(c *gin.Context) {
	id := c.Param("id")
	h.svc.MarkRead(id)
	web.Succeed(c).Send()
}

func (h *Handler) MarkAllRead(c *gin.Context) {
	user, _ := middleware.GetCurrentUser(c)
	userID := ""
	if user != nil {
		userID = user.UserID
	}

	h.svc.MarkAllRead(userID)
	web.Succeed(c).Send()
}

func (h *Handler) Delete(c *gin.Context) {
	id := c.Param("id")
	h.svc.Delete(id)
	web.Succeed(c).Send()
}

type NotifyRoutes struct {
	handler *Handler
}

func NewNotifyRoutes(handler *Handler) *NotifyRoutes {
	return &NotifyRoutes{handler: handler}
}

func (m *NotifyRoutes) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	backends := authorize.RegisterRoutes(e.Group("/notify"), []authorize.Route{
		{
			Name: "站内通知", Enabled: true,
			Children: []authorize.Route{
				{Name: "通知列表", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "未读数量", Path: "unread-count", Method: "GET", Handler: m.handler.UnreadCount, Enabled: true},
				{Name: "标记已读", Path: ":id/read", Method: "POST", Handler: m.handler.MarkRead, Enabled: true},
				{Name: "全部已读", Path: "read-all", Method: "POST", Handler: m.handler.MarkAllRead, Enabled: true},
				{Name: "删除通知", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
			},
		},
	})

	return backends
}
