package api

import (
	"encoding/json"
	"log/slog"

	"vulnscan-backend/model"
	tmplEngine "vulnscan-backend/template/engine"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"vulnscan-backend/pkg/definition"
)

type Handler struct {
	db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

type templateQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Category string `form:"category"`
}

func (h *Handler) List(c *gin.Context) {
	q, _ := web.BindQuery[templateQuery](c)
	if q.PageSize <= 0 {
		q.PageSize = 20
	}
	if q.Page <= 0 {
		q.Page = 1
	}

	scope := iamsdk.DataFilterScope(c, definition.VulnscanFieldMapping)
	tx := h.db.Model(&model.ScanTemplate{}).Scopes(scope)
	if q.Keyword != "" {
		tx = tx.Where("name LIKE ? OR description LIKE ?", "%"+q.Keyword+"%", "%"+q.Keyword+"%")
	}
	if q.Category != "" {
		tx = tx.Where("category = ?", q.Category)
	}

	var count int64
	tx.Count(&count)

	var items []model.ScanTemplate
	tx.Order("builtin DESC, created_at DESC").Offset((q.Page - 1) * q.PageSize).Limit(q.PageSize).Find(&items)

	type tmplVO struct {
		model.ScanTemplate
		Stages []tmplEngine.TemplateStage `json:"stages,omitempty"`
		Params []tmplEngine.TemplateParam `json:"params,omitempty"`
	}

	results := make([]tmplVO, 0, len(items))
	for _, item := range items {
		vo := tmplVO{ScanTemplate: item}
		if item.Content != "" {
			var parsed tmplEngine.ScanTemplate
			if err := json.Unmarshal([]byte(item.Content), &parsed); err == nil {
				vo.Stages = parsed.Stages
				vo.Params = parsed.Params
			}
		}
		results = append(results, vo)
	}

	web.OK(c).List(count, results).Send()
}

func (h *Handler) GetByID(c *gin.Context) {
	id := c.Param("id")
	var item model.ScanTemplate
	if err := h.db.Where("id = ?", id).First(&item).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	type detailVO struct {
		model.ScanTemplate
		Stages []tmplEngine.TemplateStage `json:"stages"`
		Params []tmplEngine.TemplateParam `json:"params"`
	}

	vo := detailVO{ScanTemplate: item}
	if item.Content != "" {
		var parsed tmplEngine.ScanTemplate
		if err := json.Unmarshal([]byte(item.Content), &parsed); err == nil {
			vo.Stages = parsed.Stages
			vo.Params = parsed.Params
		}
	}

	web.OK(c).Data(vo).Send()
}

type createTemplateReq struct {
	Name        string                     `json:"name"`
	Code        string                     `json:"code"`
	Category    string                     `json:"category"`
	Description string                     `json:"description"`
	Icon        string                     `json:"icon"`
	Tags        []string                   `json:"tags"`
	Params      []tmplEngine.TemplateParam `json:"params"`
	Stages      []tmplEngine.TemplateStage `json:"stages"`
}

func (h *Handler) Create(c *gin.Context) {
	req, ok := web.BindJSON[createTemplateReq](c)
	if !ok {
		return
	}
	if req.Name == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	content, _ := json.Marshal(tmplEngine.ScanTemplate{
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		Params:      req.Params,
		Stages:      req.Stages,
	})

	item := model.ScanTemplate{
		ID:          qulid.GenerateID(),
		Name:        req.Name,
		Code:        req.Code,
		Category:    req.Category,
		Description: req.Description,
		Icon:        req.Icon,
		Tags:        model.StringArray(req.Tags),
		Content:     string(content),
		Version:     "1.0.0",
	}

	if err := h.db.Create(&item).Error; err != nil {
		slog.Error("[Template] create failed", "error", err)
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

type updateTemplateReq struct {
	Name        string                     `json:"name"`
	Code        string                     `json:"code"`
	Category    string                     `json:"category"`
	Description string                     `json:"description"`
	Icon        string                     `json:"icon"`
	Tags        []string                   `json:"tags"`
	Params      []tmplEngine.TemplateParam `json:"params"`
	Stages      []tmplEngine.TemplateStage `json:"stages"`
	Enabled     *bool                      `json:"enabled"`
}

func (h *Handler) Update(c *gin.Context) {
	id := c.Param("id")

	var existing model.ScanTemplate
	if err := h.db.Where("id = ?", id).First(&existing).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	req, ok := web.BindJSON[updateTemplateReq](c)
	if !ok {
		return
	}

	updates := map[string]interface{}{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Code != "" {
		updates["code"] = req.Code
	}
	if req.Category != "" {
		updates["category"] = req.Category
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.Icon != "" {
		updates["icon"] = req.Icon
	}
	if req.Tags != nil {
		updates["tags"] = model.StringArray(req.Tags)
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}

	if req.Params != nil || req.Stages != nil {
		var parsed tmplEngine.ScanTemplate
		if existing.Content != "" {
			_ = json.Unmarshal([]byte(existing.Content), &parsed)
		}
		if req.Params != nil {
			parsed.Params = req.Params
		}
		if req.Stages != nil {
			parsed.Stages = req.Stages
		}
		content, _ := json.Marshal(parsed)
		updates["content"] = string(content)
	}

	if err := h.db.Model(&model.ScanTemplate{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) Delete(c *gin.Context) {
	id := c.Param("id")

	var item model.ScanTemplate
	if err := h.db.Where("id = ?", id).First(&item).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	if item.Builtin {
		web.Err(c, web.InternalError).Send()
		return
	}

	if err := h.db.Where("id = ?", id).Delete(&model.ScanTemplate{}).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

type toggleTemplateReq struct {
	Enabled bool `json:"enabled"`
}

func (h *Handler) Toggle(c *gin.Context) {
	id := c.Param("id")
	req, ok := web.BindJSON[toggleTemplateReq](c)
	if !ok {
		return
	}

	if err := h.db.Model(&model.ScanTemplate{}).Where("id = ?", id).Update("enabled", req.Enabled).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *Handler) SeedBuiltins(c *gin.Context) {
	builtins := tmplEngine.BuiltinTemplates()
	updated, created := 0, 0
	for _, bt := range builtins {
		content, _ := json.Marshal(bt)
		var count int64
		h.db.Model(&model.ScanTemplate{}).Where("id = ? OR code = ?", bt.ID, bt.ID).Count(&count)
		if count > 0 {
			h.db.Model(&model.ScanTemplate{}).Where("id = ? OR code = ?", bt.ID, bt.ID).
				Updates(map[string]interface{}{
					"content":     string(content),
					"version":     bt.Version,
					"name":        bt.Name,
					"description": bt.Description,
				})
			updated++
			continue
		}
		item := model.ScanTemplate{
			ID:          bt.ID,
			Name:        bt.Name,
			Code:        bt.ID,
			Category:    "builtin",
			Description: bt.Description,
			Tags:        model.StringArray(bt.Tags),
			Content:     string(content),
			Version:     bt.Version,
			Builtin:     true,
			Enabled:     true,
			AuthorID:    "system",
		}
		if item.ID == "" {
			item.ID = qulid.GenerateID()
		}
		h.db.Create(&item)
		created++
	}
	slog.Info("[Template] 内置模板同步完成", "updated", updated, "created", created)
	web.OK(c).Data(map[string]int{"updated": updated, "created": created}).Send()
}

func (h *Handler) ListBuiltins(c *gin.Context) {
	builtins := tmplEngine.BuiltinTemplates()
	web.OK(c).Data(builtins).Send()
}
