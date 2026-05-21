package datalib

import (
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
)

type knowledgeReloader interface {
	ReloadAll() error
}

type HandlerDataLib struct {
	svc       *ServiceDataLib
	knowledge knowledgeReloader
}

func NewHandlerDataLib(svc *ServiceDataLib, knowledge knowledgeReloader) *HandlerDataLib {
	return &HandlerDataLib{svc: svc, knowledge: knowledge}
}

func (h *HandlerDataLib) reloadScanKnowledge() {
	if h.knowledge != nil {
		if err := h.knowledge.ReloadAll(); err != nil {
			// logged inside ReloadAll
			return
		}
	}
}

func (h *HandlerDataLib) List(c *gin.Context) {
	query, ok := web.BindQuery[DataLibQuery](c)
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

func (h *HandlerDataLib) GetByID(c *gin.Context) {
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

func (h *HandlerDataLib) Create(c *gin.Context) {
	req, ok := web.BindJSON[model.DataLibrary](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	req.CreatedBy = user.UserID
	req.OrganizeID = user.OrganizeID
	if err := h.svc.Create(&req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(req).Send()
}

func (h *HandlerDataLib) Update(c *gin.Context) {
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

func (h *HandlerDataLib) Delete(c *gin.Context) {
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

// ── Entry Handlers ──

type entryUri struct {
	ID      string `uri:"id" binding:"required"`
	EntryID string `uri:"entry_id"`
}

func (h *HandlerDataLib) ListEntries(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	query, ok := web.BindQuery[EntryQuery](c)
	if !ok {
		return
	}
	items, count, err := h.svc.ListEntries(uri.Id, query)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerDataLib) GetEntry(c *gin.Context) {
	uri, ok := web.BindUri[entryUri](c)
	if !ok {
		return
	}
	item, err := h.svc.GetEntryByID(uri.EntryID)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerDataLib) AddEntry(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	entry, ok := web.BindJSON[model.DataLibraryEntry](c)
	if !ok {
		return
	}
	if err := h.svc.AddEntry(uri.Id, &entry); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	h.reloadScanKnowledge()
	web.OK(c).Data(entry).Send()
}

func (h *HandlerDataLib) UpdateEntry(c *gin.Context) {
	uri, ok := web.BindUri[entryUri](c)
	if !ok {
		return
	}
	updates, ok := web.BindJSON[map[string]any](c)
	if !ok {
		return
	}
	if err := h.svc.UpdateEntry(uri.EntryID, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	h.reloadScanKnowledge()
	web.OK(c).Send()
}

func (h *HandlerDataLib) DeleteEntry(c *gin.Context) {
	uri, ok := web.BindUri[entryUri](c)
	if !ok {
		return
	}
	if err := h.svc.DeleteEntry(uri.EntryID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	h.reloadScanKnowledge()
	web.OK(c).Send()
}

type batchEntryReq struct {
	Entries []model.DataLibraryEntry `json:"entries" binding:"required"`
}

func (h *HandlerDataLib) BatchAddEntries(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[batchEntryReq](c)
	if !ok {
		return
	}
	count, err := h.svc.BatchAddEntries(uri.Id, req.Entries)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	h.reloadScanKnowledge()
	web.OK(c).Data(gin.H{"created": count}).Send()
}

// ── Bulk Operations ──

type importReq struct {
	Text string `json:"text" binding:"required"`
}

func (h *HandlerDataLib) Import(c *gin.Context) {
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
	h.reloadScanKnowledge()
	web.OK(c).Data(gin.H{"imported": count}).Send()
}

func (h *HandlerDataLib) Export(c *gin.Context) {
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
	c.Header("Content-Disposition", "attachment; filename=datalib-export.txt")
	c.String(200, text)
}

func (h *HandlerDataLib) Clear(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.ClearEntries(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	h.reloadScanKnowledge()
	web.OK(c).Send()
}

func (h *HandlerDataLib) GetCategories(c *gin.Context) {
	libType := c.Query("type")
	categories, err := h.svc.GetCategories(libType)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(categories).Send()
}

func (h *HandlerDataLib) Reload(c *gin.Context) {
	if h.knowledge == nil {
		web.Fail(c).Msg("扫描知识库未初始化").Send()
		return
	}
	if err := h.knowledge.ReloadAll(); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Msg("reload success").Send()
}
