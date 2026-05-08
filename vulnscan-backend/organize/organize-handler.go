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
	var req oc.OrganizeListReq
	if err := c.ShouldBindQuery(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	items, count, err := h.svc.List(req)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *HandlerOrganize) GetByID(c *gin.Context) {
	item, err := h.svc.GetByID(c.Param("id"))
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, item)
}

func (h *HandlerOrganize) Create(c *gin.Context) {
	var item model.Organize
	if !web.ValidationJson(c, &item) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item.CreatedBy = user.UserID
	if err := h.svc.Create(&item); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, item)
}

func (h *HandlerOrganize) Update(c *gin.Context) {
	id := c.Param("id")
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if err := h.svc.Update(id, body); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerOrganize) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Param("id")); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerOrganize) Tree(c *gin.Context) {
	items, err := h.svc.Tree()
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, items)
}

// ── 建设运维单位 Handler ──

type HandlerConstruction struct {
	svc oc.ServiceConstruction
}

func NewHandlerConstruction(svc oc.ServiceConstruction) *HandlerConstruction {
	return &HandlerConstruction{svc: svc}
}

func (h *HandlerConstruction) List(c *gin.Context) {
	var req oc.ConstructionListReq
	if err := c.ShouldBindQuery(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	items, count, err := h.svc.List(req)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *HandlerConstruction) GetByID(c *gin.Context) {
	item, err := h.svc.GetByID(c.Param("id"))
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, item)
}

func (h *HandlerConstruction) Create(c *gin.Context) {
	var item model.ConstructionOrg
	if !web.ValidationJson(c, &item) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item.CreatedBy = user.UserID
	if err := h.svc.Create(&item); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, item)
}

func (h *HandlerConstruction) Update(c *gin.Context) {
	id := c.Param("id")
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if err := h.svc.Update(id, body); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerConstruction) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Param("id")); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}
