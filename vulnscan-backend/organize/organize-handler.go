package organize

import (
	"vulnscan-backend/model"
	oc "vulnscan-backend/organize/organize-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

// ── 组织 Handler ──

type HandlerOrganize struct {
	svc oc.ServiceOrganize
}

func NewHandlerOrganize(svc oc.ServiceOrganize) *HandlerOrganize {
	return &HandlerOrganize{svc: svc}
}

func (h *HandlerOrganize) List(c *gin.Context) {
	req, ok := web.BindQuery[oc.OrganizeListReq](c)
	if !ok {
		return
	}
	items, count, err := h.svc.List(req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerOrganize) GetByID(c *gin.Context) {
	item, err := h.svc.GetByID(c.Param("id"))
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerOrganize) Create(c *gin.Context) {
	var item model.Organize
	if !web.ValidationJson(c, &item) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item.CreatedBy = user.UserID
	if err := h.svc.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerOrganize) Update(c *gin.Context) {
	id := c.Param("id")
	body, ok := web.BindJSON[map[string]interface{}](c)
	if !ok {
		return
	}
	if err := h.svc.Update(id, body); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerOrganize) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Param("id")); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerOrganize) Tree(c *gin.Context) {
	items, err := h.svc.Tree()
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(items).Send()
}

// ── 建设运维单位 Handler ──

type HandlerConstruction struct {
	svc oc.ServiceConstruction
}

func NewHandlerConstruction(svc oc.ServiceConstruction) *HandlerConstruction {
	return &HandlerConstruction{svc: svc}
}

func (h *HandlerConstruction) List(c *gin.Context) {
	req, ok := web.BindQuery[oc.ConstructionListReq](c)
	if !ok {
		return
	}
	items, count, err := h.svc.List(req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerConstruction) GetByID(c *gin.Context) {
	item, err := h.svc.GetByID(c.Param("id"))
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerConstruction) Create(c *gin.Context) {
	var item model.ConstructionOrg
	if !web.ValidationJson(c, &item) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item.CreatedBy = user.UserID
	if err := h.svc.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerConstruction) Update(c *gin.Context) {
	id := c.Param("id")
	body, ok := web.BindJSON[map[string]interface{}](c)
	if !ok {
		return
	}
	if err := h.svc.Update(id, body); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerConstruction) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Param("id")); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
