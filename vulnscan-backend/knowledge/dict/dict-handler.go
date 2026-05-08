package dict

import (
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
)

type HandlerDict struct {
	svc *ServiceDict
}

func NewHandlerDict(svc *ServiceDict) *HandlerDict {
	return &HandlerDict{svc: svc}
}

func (h *HandlerDict) List(c *gin.Context) {
	query, ok := web.BindQuery[DictQuery](c)
	if !ok {
		return
	}
	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	items, count, err := h.svc.List(query, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerDict) GetByID(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	item, err := h.svc.GetByID(uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerDict) Create(c *gin.Context) {
	req, ok := web.BindJSON[model.Dictionary](c)
	if !ok {
		return
	}
	if err := h.svc.Create(&req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(req).Send()
}

func (h *HandlerDict) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	updates, ok := web.BindJSON[map[string]any](c)
	if !ok {
		return
	}
	if err := h.svc.Update(uri.Id, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerDict) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Delete(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

type entryQuery struct {
	Page     int `form:"page"`
	PageSize int `form:"page_size"`
}

type entryUri struct {
	ID      string `uri:"id" binding:"required"`
	EntryID string `uri:"entry_id"`
}

func (h *HandlerDict) ListEntries(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	query, ok := web.BindQuery[entryQuery](c)
	if !ok {
		return
	}
	items, count, err := h.svc.ListEntries(uri.Id, query.Page, query.PageSize)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerDict) AddEntry(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	entry, ok := web.BindJSON[model.DictionaryEntry](c)
	if !ok {
		return
	}
	if err := h.svc.AddEntry(uri.Id, &entry); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(entry).Send()
}

func (h *HandlerDict) DeleteEntry(c *gin.Context) {
	uri, ok := web.BindUri[entryUri](c)
	if !ok {
		return
	}
	if uri.EntryID == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}
	if err := h.svc.DeleteEntry(uri.EntryID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

type importReq struct {
	Text string `json:"text" binding:"required"`
}

func (h *HandlerDict) Import(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[importReq](c)
	if !ok {
		return
	}
	count, err := h.svc.ImportText(uri.Id, req.Text)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"imported": count}).Send()
}

func (h *HandlerDict) Export(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	text, err := h.svc.ExportText(uri.Id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=dict-export.txt")
	c.String(200, text)
}

func (h *HandlerDict) Clear(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.ClearEntries(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
