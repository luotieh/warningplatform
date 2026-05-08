package api

import (
	"encoding/json"
	"log/slog"

	"vulnscan-backend/model"
	tmplEngine "vulnscan-backend/template/engine"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
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
	var q templateQuery
	_ = c.ShouldBindQuery(&q)
	if q.PageSize <= 0 {
		q.PageSize = 20
	}
	if q.Page <= 0 {
		q.Page = 1
	}

	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
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

	web.RespContentWithNum(c, web.Success, count, results)
}

func (h *Handler) GetByID(c *gin.Context) {
	id := c.Param("id")
	var item model.ScanTemplate
	if err := h.db.Where("id = ?", id).First(&item).Error; err != nil {
		web.Resp(c, web.NotFound)
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

	web.RespContent(c, web.Success, vo)
}

func (h *Handler) Create(c *gin.Context) {
	var req struct {
		Name        string                     `json:"name"`
		Code        string                     `json:"code"`
		Category    string                     `json:"category"`
		Description string                     `json:"description"`
		Icon        string                     `json:"icon"`
		Tags        []string                   `json:"tags"`
		Params      []tmplEngine.TemplateParam `json:"params"`
		Stages      []tmplEngine.TemplateStage `json:"stages"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if req.Name == "" {
		web.Resp(c, web.ParamsMissingRequired)
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
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, item)
}

func (h *Handler) Update(c *gin.Context) {
	id := c.Param("id")

	var existing model.ScanTemplate
	if err := h.db.Where("id = ?", id).First(&existing).Error; err != nil {
		web.Resp(c, web.NotFound)
		return
	}

	var req struct {
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
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
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
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) Delete(c *gin.Context) {
	id := c.Param("id")

	var item model.ScanTemplate
	if err := h.db.Where("id = ?", id).First(&item).Error; err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	if item.Builtin {
		web.Resp(c, web.InternalError)
		return
	}

	if err := h.db.Where("id = ?", id).Delete(&model.ScanTemplate{}).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) Toggle(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if err := h.db.Model(&model.ScanTemplate{}).Where("id = ?", id).Update("enabled", req.Enabled).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) SeedBuiltins(c *gin.Context) {
	builtins := tmplEngine.BuiltinTemplates()
	for _, bt := range builtins {
		var exists model.ScanTemplate
		if err := h.db.Where("code = ?", bt.ID).First(&exists).Error; err == nil {
			continue
		}

		content, _ := json.Marshal(bt)
		item := model.ScanTemplate{
			ID:          qulid.GenerateID(),
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
		h.db.Create(&item)
	}
	web.Resp(c, web.Success)
}

func (h *Handler) ListBuiltins(c *gin.Context) {
	builtins := tmplEngine.BuiltinTemplates()
	web.RespContent(c, web.Success, builtins)
}
