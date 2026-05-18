package tagging

import (
	"strconv"

	"vulnscan-backend/model"
	tc "vulnscan-backend/tagging/tagging-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
)

type HandlerTag struct {
	svc tc.ServiceTag
}

func NewHandlerTag(svc tc.ServiceTag) *HandlerTag {
	return &HandlerTag{svc: svc}
}

func (h *HandlerTag) List(c *gin.Context) {
	req, ok := web.BindQuery[tc.TagListReq](c)
	if !ok {
		return
	}
	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	items, count, err := h.svc.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerTag) GetByID(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	item, err := h.svc.GetByID(id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerTag) Create(c *gin.Context) {
	tag, ok := web.BindJSON[model.Tag](c)
	if !ok {
		return
	}
	if err := h.svc.Create(&tag); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(tag).Send()
}

func (h *HandlerTag) Update(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
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

func (h *HandlerTag) Delete(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := h.svc.Delete(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerTag) GetAssetTags(c *gin.Context) {
	tags, err := h.svc.GetAssetTags(c.Param("asset_id"))
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(tags).Send()
}

func (h *HandlerTag) SetAssetTags(c *gin.Context) {
	req, ok := web.BindJSON[tc.AssetTagReq](c)
	if !ok {
		return
	}
	if err := h.svc.SetAssetTags(req.AssetID, req.TagIDs, "manual"); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ── ChangeLog Handler ──

type HandlerChangeLog struct {
	svc tc.ServiceChangeLog
}

func NewHandlerChangeLog(svc tc.ServiceChangeLog) *HandlerChangeLog {
	return &HandlerChangeLog{svc: svc}
}

func (h *HandlerChangeLog) List(c *gin.Context) {
	req, ok := web.BindQuery[tc.ChangeLogListReq](c)
	if !ok {
		return
	}
	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	items, count, err := h.svc.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerChangeLog) GetByAssetID(c *gin.Context) {
	items, err := h.svc.GetByAssetID(c.Param("asset_id"))
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(items).Send()
}
