package payloadmgr

import (
	"strconv"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type PayloadQuery struct {
	Page     int    `form:"page,default=1"`
	PageSize int    `form:"page_size,default=20"`
	Category string `form:"category"`
	Type     string `form:"type"`
	Enabled  *bool  `form:"enabled"`
	Keyword  string `form:"keyword"`
}

type PatternQuery struct {
	Page     int    `form:"page,default=1"`
	PageSize int    `form:"page_size,default=20"`
	Category string `form:"category"`
	Enabled  *bool  `form:"enabled"`
	Keyword  string `form:"keyword"`
}

type ConfigQuery struct {
	Category string `form:"category"`
	Enabled  *bool  `form:"enabled"`
}

func parseUintID(idStr string) (uint, error) {
	v, err := strconv.ParseUint(idStr, 10, 64)
	return uint(v), err
}

type Handler struct {
	svc    *Service
	loader interface{}
}

func NewHandler(svc *Service, loader interface{}) *Handler {
	return &Handler{svc: svc, loader: loader}
}

func (h *Handler) ListPayloads(c *gin.Context) {
	query, ok := web.BindQuery[PayloadQuery](c)
	if !ok {
		return
	}

	items, total, err := h.svc.ListPayloads(&query)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, items).Send()
}

func (h *Handler) GetPayloadByID(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	id, err := parseUintID(uri.Id)
	if err != nil {
		web.Fail(c).Msg("invalid id").Send()
		return
	}
	item, err := h.svc.GetPayloadByID(id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) CreatePayload(c *gin.Context) {
	req, ok := web.BindJSON[model.VulnPayload](c)
	if !ok {
		return
	}
	if err := h.svc.CreatePayload(&req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Data(req).Send()
}

func (h *Handler) UpdatePayload(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	id, err := parseUintID(uri.Id)
	if err != nil {
		web.Fail(c).Msg("invalid id").Send()
		return
	}
	updates, ok := web.BindJSON[map[string]any](c)
	if !ok {
		return
	}
	if err := h.svc.UpdatePayload(id, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Send()
}

func (h *Handler) DeletePayload(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	id, err := parseUintID(uri.Id)
	if err != nil {
		web.Fail(c).Msg("invalid id").Send()
		return
	}
	if err := h.svc.DeletePayload(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Send()
}

type BatchPayloadRequest struct {
	Payloads []model.VulnPayload `json:"payloads" binding:"required"`
}

func (h *Handler) BatchCreatePayloads(c *gin.Context) {
	req, ok := web.BindJSON[BatchPayloadRequest](c)
	if !ok {
		return
	}
	if err := h.svc.BatchCreatePayloads(req.Payloads); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Data(gin.H{"created": len(req.Payloads)}).Send()
}

func (h *Handler) ListPatterns(c *gin.Context) {
	query, ok := web.BindQuery[PatternQuery](c)
	if !ok {
		return
	}

	items, total, err := h.svc.ListPatterns(&query)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, items).Send()
}

func (h *Handler) GetPatternByID(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	id, err := parseUintID(uri.Id)
	if err != nil {
		web.Fail(c).Msg("invalid id").Send()
		return
	}
	item, err := h.svc.GetPatternByID(id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) CreatePattern(c *gin.Context) {
	req, ok := web.BindJSON[model.VulnPayloadPattern](c)
	if !ok {
		return
	}
	if err := h.svc.CreatePattern(&req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Data(req).Send()
}

func (h *Handler) UpdatePattern(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	id, err := parseUintID(uri.Id)
	if err != nil {
		web.Fail(c).Msg("invalid id").Send()
		return
	}
	updates, ok := web.BindJSON[map[string]any](c)
	if !ok {
		return
	}
	if err := h.svc.UpdatePattern(id, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Send()
}

func (h *Handler) DeletePattern(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	id, err := parseUintID(uri.Id)
	if err != nil {
		web.Fail(c).Msg("invalid id").Send()
		return
	}
	if err := h.svc.DeletePattern(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Send()
}

type BatchPatternRequest struct {
	Patterns []model.VulnPayloadPattern `json:"patterns" binding:"required"`
}

func (h *Handler) BatchCreatePatterns(c *gin.Context) {
	req, ok := web.BindJSON[BatchPatternRequest](c)
	if !ok {
		return
	}
	if err := h.svc.BatchCreatePatterns(req.Patterns); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Data(gin.H{"created": len(req.Patterns)}).Send()
}

func (h *Handler) ListConfigs(c *gin.Context) {
	query, ok := web.BindQuery[ConfigQuery](c)
	if !ok {
		return
	}

	items, err := h.svc.ListConfigs(&query)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(items).Send()
}

func (h *Handler) GetConfigByID(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	id, err := parseUintID(uri.Id)
	if err != nil {
		web.Fail(c).Msg("invalid id").Send()
		return
	}
	item, err := h.svc.GetConfigByID(id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *Handler) CreateConfig(c *gin.Context) {
	req, ok := web.BindJSON[model.VulnPayloadConfig](c)
	if !ok {
		return
	}
	if err := h.svc.CreateConfig(&req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Data(req).Send()
}

func (h *Handler) UpdateConfig(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	id, err := parseUintID(uri.Id)
	if err != nil {
		web.Fail(c).Msg("invalid id").Send()
		return
	}
	updates, ok := web.BindJSON[map[string]any](c)
	if !ok {
		return
	}
	if err := h.svc.UpdateConfig(id, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Send()
}

func (h *Handler) DeleteConfig(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	id, err := parseUintID(uri.Id)
	if err != nil {
		web.Fail(c).Msg("invalid id").Send()
		return
	}
	if err := h.svc.DeleteConfig(id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	_ = h.svc.ReloadPayloads(h.loader)
	web.OK(c).Send()
}

func (h *Handler) GetCategories(c *gin.Context) {
	categories, err := h.svc.GetCategories()
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(categories).Send()
}
