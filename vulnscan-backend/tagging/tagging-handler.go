package tagging

import (
	"strconv"

	"vulnscan-backend/model"
	tc "vulnscan-backend/tagging/tagging-contract"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type HandlerTag struct {
	svc tc.ServiceTag
}

func NewHandlerTag(svc tc.ServiceTag) *HandlerTag {
	return &HandlerTag{svc: svc}
}

func (h *HandlerTag) List(c *gin.Context) {
	var req tc.TagListReq
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

func (h *HandlerTag) GetByID(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	item, err := h.svc.GetByID(id)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, item)
}

func (h *HandlerTag) Create(c *gin.Context) {
	var tag model.Tag
	if err := c.ShouldBindJSON(&tag); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if err := h.svc.Create(&tag); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, tag)
}

func (h *HandlerTag) Update(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
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

func (h *HandlerTag) Delete(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := h.svc.Delete(id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *HandlerTag) GetAssetTags(c *gin.Context) {
	tags, err := h.svc.GetAssetTags(c.Param("asset_id"))
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, tags)
}

func (h *HandlerTag) SetAssetTags(c *gin.Context) {
	var req tc.AssetTagReq
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if err := h.svc.SetAssetTags(req.AssetID, req.TagIDs, "manual"); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

// ── ChangeLog Handler ──

type HandlerChangeLog struct {
	svc tc.ServiceChangeLog
}

func NewHandlerChangeLog(svc tc.ServiceChangeLog) *HandlerChangeLog {
	return &HandlerChangeLog{svc: svc}
}

func (h *HandlerChangeLog) List(c *gin.Context) {
	var req tc.ChangeLogListReq
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

func (h *HandlerChangeLog) GetByAssetID(c *gin.Context) {
	items, err := h.svc.GetByAssetID(c.Param("asset_id"))
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, items)
}
