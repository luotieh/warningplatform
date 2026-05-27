package prompt

import (
	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc Service
}

func NewHandler(svc Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Create(c *gin.Context) {
	req, ok := web.BindJSON[CreateReq](c)
	if !ok {
		return
	}
	if err := h.svc.Create(c.Request.Context(), req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[UpdateReq](c)
	if !ok {
		return
	}
	if err := h.svc.Update(c.Request.Context(), uri.Id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Delete(c.Request.Context(), uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) Detail(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	item, err := h.svc.GetDetail(c.Request.Context(), uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) List(c *gin.Context) {
	req, ok := web.BindQuery[ListReq](c)
	if !ok {
		return
	}
	items, count, err := h.svc.List(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *Handler) Toggle(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Toggle(c.Request.Context(), uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) GetByScene(c *gin.Context) {
	query, ok := web.BindQuery[struct {
		Scene string `form:"scene" binding:"required"`
	}](c)
	if !ok {
		return
	}
	item, err := h.svc.GetByScene(c.Request.Context(), query.Scene)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}
