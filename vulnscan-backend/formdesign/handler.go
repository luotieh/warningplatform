package formdesign

import (
	"errors"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	formVersionDraft     = "draft"
	formVersionPublished = "published"
	formVersionArchived  = "archived"
)

type Handler struct {
	db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

type templateListReq struct {
	Page       int    `form:"page"`
	PageSize   int    `form:"page_size"`
	Keyword    string `form:"keyword"`
	Business   string `form:"business"`
	ObjectType string `form:"object_type"`
	Enabled    string `form:"enabled"`
}

type templateSaveReq struct {
	Name        string        `json:"name" binding:"required"`
	Code        string        `json:"code"`
	Business    string        `json:"business" binding:"required"`
	ObjectType  string        `json:"object_type"`
	Description string        `json:"description"`
	Schema      model.JSONMap `json:"schema"`
	Options     model.JSONMap `json:"options"`
	Version     int           `json:"version"`
	Enabled     *bool         `json:"enabled"`
	IsDefault   bool          `json:"is_default"`
}

type versionSaveReq struct {
	Schema    model.JSONMap `json:"schema"`
	Options   model.JSONMap `json:"options"`
	ChangeLog string        `json:"change_log"`
}

type templateURI struct {
	ID string `uri:"id" binding:"required"`
}

type versionURI struct {
	ID        string `uri:"id" binding:"required"`
	VersionID string `uri:"versionId" binding:"required"`
}

type submissionListReq struct {
	Page       int    `form:"page"`
	PageSize   int    `form:"page_size"`
	TemplateID string `form:"template_id"`
	Business   string `form:"business"`
	ObjectID   string `form:"object_id"`
	ObjectType string `form:"object_type"`
}

type submissionSaveReq struct {
	TemplateID        string        `json:"template_id" binding:"required"`
	TemplateVersionID string        `json:"template_version_id"`
	Business          string        `json:"business" binding:"required"`
	ObjectID          string        `json:"object_id" binding:"required"`
	ObjectType        string        `json:"object_type"`
	FormData          model.JSONMap `json:"form_data"`
	Version           int           `json:"version"`
}

type submissionURI struct {
	ID string `uri:"id" binding:"required"`
}

func (h *Handler) ListTemplates(c *gin.Context) {
	req, ok := web.BindQuery[templateListReq](c)
	if !ok {
		return
	}
	page, size := normalizePage(req.Page, req.PageSize)
	tx := h.db.Model(&model.DynamicFormTemplate{})
	if req.Keyword != "" {
		like := "%" + req.Keyword + "%"
		tx = tx.Where("name LIKE ? OR code LIKE ? OR description LIKE ?", like, like, like)
	}
	if req.Business != "" {
		tx = tx.Where("business = ?", req.Business)
	}
	if req.ObjectType != "" {
		tx = tx.Where("object_type = ?", req.ObjectType)
	}
	if req.Enabled != "" {
		tx = tx.Where("enabled = ?", req.Enabled != "false")
	}

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	var items []model.DynamicFormTemplate
	if err := tx.Order("business ASC, object_type ASC, updated_at DESC").
		Offset((page - 1) * size).
		Limit(size).
		Find(&items).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *Handler) GetTemplate(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	item, err := h.getTemplateWithEditableVersion(uri.ID)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, item)
}

func (h *Handler) CreateTemplate(c *gin.Context) {
	req, ok := web.BindJSON[templateSaveReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	if req.Code == "" {
		req.Code = qulid.GenerateID()
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	now := time.Now()
	item := model.DynamicFormTemplate{
		ID:          qulid.GenerateID(),
		Name:        req.Name,
		Code:        req.Code,
		Business:    req.Business,
		ObjectType:  req.ObjectType,
		Description: req.Description,
		Schema:      req.Schema,
		Options:     req.Options,
		Version:     firstPositive(req.Version, 1),
		Enabled:     enabled,
		IsDefault:   req.IsDefault,
		CreatedBy:   user.UserID,
		UpdatedBy:   user.UserID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if item.IsDefault {
			if err := clearDefault(tx, item.Business, item.ObjectType); err != nil {
				return err
			}
		}
		if err := tx.Create(&item).Error; err != nil {
			return err
		}
		draft := model.DynamicFormTemplateVersion{
			ID:          qulid.GenerateID(),
			TemplateID:  item.ID,
			Version:     item.Version,
			Status:      formVersionPublished,
			Schema:      req.Schema,
			Options:     req.Options,
			ChangeLog:   "初始版本",
			CreatedBy:   user.UserID,
			UpdatedBy:   user.UserID,
			PublishedBy: user.UserID,
			PublishedAt: &now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := tx.Create(&draft).Error; err != nil {
			return err
		}
		return tx.Model(&model.DynamicFormTemplate{}).Where("id = ?", item.ID).Updates(map[string]any{
			"current_version_id": draft.ID,
		}).Error
	}); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	created, _ := h.getTemplateWithEditableVersion(item.ID)
	web.RespContent(c, web.Success, created)
}

func (h *Handler) UpdateTemplate(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[templateSaveReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	now := time.Now()
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		var item model.DynamicFormTemplate
		if err := tx.First(&item, "id = ?", uri.ID).Error; err != nil {
			return err
		}
		if req.IsDefault {
			if err := clearDefault(tx, req.Business, req.ObjectType); err != nil {
				return err
			}
		}
		updates := map[string]any{
			"name":        req.Name,
			"business":    req.Business,
			"object_type": req.ObjectType,
			"description": req.Description,
			"is_default":  req.IsDefault,
			"updated_by":  user.UserID,
			"updated_at":  now,
		}
		if req.Code != "" {
			updates["code"] = req.Code
		}
		if req.Enabled != nil {
			updates["enabled"] = *req.Enabled
		}
		if err := tx.Model(&model.DynamicFormTemplate{}).Where("id = ?", uri.ID).Updates(updates).Error; err != nil {
			return err
		}
		if req.Schema != nil || req.Options != nil {
			draft, err := h.ensureDraftVersion(tx, item, user.UserID)
			if err != nil {
				return err
			}
			versionUpdates := map[string]any{
				"updated_by": user.UserID,
				"updated_at": now,
			}
			if req.Schema != nil {
				versionUpdates["schema"] = req.Schema
				versionUpdates["change_log"] = "更新草稿"
			}
			if req.Options != nil {
				versionUpdates["options"] = req.Options
			}
			return tx.Model(&model.DynamicFormTemplateVersion{}).Where("id = ?", draft.ID).Updates(versionUpdates).Error
		}
		return nil
	}); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) DeleteTemplate(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&model.DynamicFormTemplateVersion{}, "template_id = ?", uri.ID).Error; err != nil {
			return err
		}
		return tx.Delete(&model.DynamicFormTemplate{}, "id = ?", uri.ID).Error
	}); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) ListVersions(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	var items []model.DynamicFormTemplateVersion
	if err := h.db.Where("template_id = ?", uri.ID).Order("version DESC, updated_at DESC").Find(&items).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, items)
}

func (h *Handler) GetVersion(c *gin.Context) {
	uri, ok := web.BindUri[versionURI](c)
	if !ok {
		return
	}
	var item model.DynamicFormTemplateVersion
	if err := h.db.First(&item, "id = ? AND template_id = ?", uri.VersionID, uri.ID).Error; err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, item)
}

func (h *Handler) SaveDraft(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[versionSaveReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	var draft model.DynamicFormTemplateVersion
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		var item model.DynamicFormTemplate
		if err := tx.First(&item, "id = ?", uri.ID).Error; err != nil {
			return err
		}
		var err error
		draft, err = h.ensureDraftVersion(tx, item, user.UserID)
		if err != nil {
			return err
		}
		return tx.Model(&model.DynamicFormTemplateVersion{}).Where("id = ?", draft.ID).Updates(map[string]any{
			"schema":     req.Schema,
			"options":    req.Options,
			"change_log": req.ChangeLog,
			"updated_by": user.UserID,
			"updated_at": time.Now(),
		}).Error
	}); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"id": draft.ID})
}

func (h *Handler) CreateDraft(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	var draft model.DynamicFormTemplateVersion
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		var item model.DynamicFormTemplate
		if err := tx.First(&item, "id = ?", uri.ID).Error; err != nil {
			return err
		}
		var err error
		draft, err = h.ensureDraftVersion(tx, item, user.UserID)
		return err
	}); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, draft)
}

func (h *Handler) PublishDraft(c *gin.Context) {
	uri, ok := web.BindUri[templateURI](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[versionSaveReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	var published model.DynamicFormTemplateVersion
	now := time.Now()
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		var item model.DynamicFormTemplate
		if err := tx.First(&item, "id = ?", uri.ID).Error; err != nil {
			return err
		}
		draft, err := h.ensureDraftVersion(tx, item, user.UserID)
		if err != nil {
			return err
		}
		updates := map[string]any{
			"status":       formVersionPublished,
			"schema":       req.Schema,
			"options":      req.Options,
			"change_log":   req.ChangeLog,
			"published_by": user.UserID,
			"published_at": &now,
			"updated_by":   user.UserID,
			"updated_at":   now,
		}
		if err := tx.Model(&model.DynamicFormTemplateVersion{}).Where("id = ?", draft.ID).Updates(updates).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.DynamicFormTemplateVersion{}).
			Where("template_id = ? AND id <> ? AND status = ?", item.ID, draft.ID, formVersionPublished).
			Update("status", formVersionArchived).Error; err != nil {
			return err
		}
		if err := tx.First(&published, "id = ?", draft.ID).Error; err != nil {
			return err
		}
		return tx.Model(&model.DynamicFormTemplate{}).Where("id = ?", item.ID).Updates(map[string]any{
			"schema":             req.Schema,
			"options":            req.Options,
			"version":            published.Version,
			"current_version_id": published.ID,
			"draft_version_id":   "",
			"updated_by":         user.UserID,
			"updated_at":         now,
		}).Error
	}); err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, published)
}

func (h *Handler) ListSubmissions(c *gin.Context) {
	req, ok := web.BindQuery[submissionListReq](c)
	if !ok {
		return
	}
	page, size := normalizePage(req.Page, req.PageSize)
	tx := h.db.Model(&model.DynamicFormSubmission{})
	if req.TemplateID != "" {
		tx = tx.Where("template_id = ?", req.TemplateID)
	}
	if req.Business != "" {
		tx = tx.Where("business = ?", req.Business)
	}
	if req.ObjectID != "" {
		tx = tx.Where("object_id = ?", req.ObjectID)
	}
	if req.ObjectType != "" {
		tx = tx.Where("object_type = ?", req.ObjectType)
	}
	var count int64
	if err := tx.Count(&count).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	var items []model.DynamicFormSubmission
	if err := tx.Order("updated_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *Handler) GetSubmission(c *gin.Context) {
	uri, ok := web.BindUri[submissionURI](c)
	if !ok {
		return
	}
	var item model.DynamicFormSubmission
	if err := h.db.First(&item, "id = ?", uri.ID).Error; err != nil {
		web.Resp(c, web.NotFound)
		return
	}
	var version model.DynamicFormTemplateVersion
	if item.TemplateVersionID != "" {
		_ = h.db.First(&version, "id = ?", item.TemplateVersionID).Error
	}
	web.RespContent(c, web.Success, gin.H{"submission": item, "version": version})
}

func (h *Handler) SaveSubmission(c *gin.Context) {
	req, ok := web.BindJSON[submissionSaveReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	now := time.Now()
	versionID, versionNumber, err := h.resolveSubmissionVersion(req.TemplateID, req.TemplateVersionID)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	var existing model.DynamicFormSubmission
	err = h.db.Where("template_id = ? AND business = ? AND object_id = ?", req.TemplateID, req.Business, req.ObjectID).First(&existing).Error
	if err == nil {
		if existing.TemplateVersionID != "" {
			versionID = existing.TemplateVersionID
			versionNumber = firstPositive(existing.Version, versionNumber)
		}
		if err := h.db.Model(&model.DynamicFormSubmission{}).Where("id = ?", existing.ID).Updates(map[string]any{
			"template_version_id": versionID,
			"object_type":         req.ObjectType,
			"form_data":           req.FormData,
			"version":             firstPositive(req.Version, versionNumber, existing.Version),
			"updated_by":          user.UserID,
			"updated_at":          now,
		}).Error; err != nil {
			web.Resp(c, web.InternalError)
			return
		}
		web.RespContent(c, web.Success, gin.H{"id": existing.ID, "template_version_id": versionID})
		return
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		web.Resp(c, web.InternalError)
		return
	}
	item := model.DynamicFormSubmission{
		ID:                qulid.GenerateID(),
		TemplateID:        req.TemplateID,
		TemplateVersionID: versionID,
		Business:          req.Business,
		ObjectID:          req.ObjectID,
		ObjectType:        req.ObjectType,
		FormData:          req.FormData,
		Version:           firstPositive(req.Version, versionNumber, 1),
		CreatedBy:         user.UserID,
		UpdatedBy:         user.UserID,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := h.db.Create(&item).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.RespContent(c, web.Success, gin.H{"id": item.ID, "template_version_id": versionID})
}

func (h *Handler) DeleteSubmission(c *gin.Context) {
	uri, ok := web.BindUri[submissionURI](c)
	if !ok {
		return
	}
	if err := h.db.Delete(&model.DynamicFormSubmission{}, "id = ?", uri.ID).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) getTemplateWithEditableVersion(id string) (model.DynamicFormTemplate, error) {
	var item model.DynamicFormTemplate
	if err := h.db.First(&item, "id = ?", id).Error; err != nil {
		return item, err
	}
	var version model.DynamicFormTemplateVersion
	if item.DraftVersionID != "" {
		if err := h.db.First(&version, "id = ?", item.DraftVersionID).Error; err == nil {
			item.Schema = version.Schema
			item.Options = version.Options
			item.Version = version.Version
			return item, nil
		}
	}
	if item.CurrentVersionID != "" {
		if err := h.db.First(&version, "id = ?", item.CurrentVersionID).Error; err == nil {
			item.Schema = version.Schema
			item.Options = version.Options
			item.Version = version.Version
		}
	}
	return item, nil
}

func (h *Handler) ensureDraftVersion(tx *gorm.DB, item model.DynamicFormTemplate, userID string) (model.DynamicFormTemplateVersion, error) {
	if item.DraftVersionID != "" {
		var draft model.DynamicFormTemplateVersion
		if err := tx.First(&draft, "id = ? AND status = ?", item.DraftVersionID, formVersionDraft).Error; err == nil {
			return draft, nil
		}
	}
	baseVersion := item.Version
	baseSchema := item.Schema
	baseOptions := item.Options
	if item.CurrentVersionID != "" {
		var current model.DynamicFormTemplateVersion
		if err := tx.First(&current, "id = ?", item.CurrentVersionID).Error; err == nil {
			baseVersion = current.Version
			baseSchema = current.Schema
			baseOptions = current.Options
		}
	}
	nextVersion := firstPositive(baseVersion, 0) + 1
	if item.CurrentVersionID == "" {
		nextVersion = firstPositive(item.Version, 1)
	}
	now := time.Now()
	draft := model.DynamicFormTemplateVersion{
		ID:         qulid.GenerateID(),
		TemplateID: item.ID,
		Version:    nextVersion,
		Status:     formVersionDraft,
		Schema:     baseSchema,
		Options:    baseOptions,
		ChangeLog:  "新建草稿",
		CreatedBy:  userID,
		UpdatedBy:  userID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := tx.Create(&draft).Error; err != nil {
		return draft, err
	}
	if err := tx.Model(&model.DynamicFormTemplate{}).Where("id = ?", item.ID).Update("draft_version_id", draft.ID).Error; err != nil {
		return draft, err
	}
	return draft, nil
}

func (h *Handler) resolveSubmissionVersion(templateID, versionID string) (string, int, error) {
	if versionID != "" {
		var version model.DynamicFormTemplateVersion
		if err := h.db.First(&version, "id = ? AND template_id = ?", versionID, templateID).Error; err != nil {
			return "", 1, err
		}
		return version.ID, version.Version, nil
	}
	var item model.DynamicFormTemplate
	if err := h.db.First(&item, "id = ?", templateID).Error; err != nil {
		return "", 1, err
	}
	if item.CurrentVersionID == "" {
		return "", firstPositive(item.Version, 1), nil
	}
	var version model.DynamicFormTemplateVersion
	if err := h.db.First(&version, "id = ?", item.CurrentVersionID).Error; err != nil {
		return "", firstPositive(item.Version, 1), nil
	}
	return version.ID, version.Version, nil
}

func normalizePage(page, size int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 20
	}
	return page, size
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 1
}

func clearDefault(tx *gorm.DB, business, objectType string) error {
	return tx.Model(&model.DynamicFormTemplate{}).
		Where("business = ? AND object_type = ?", business, objectType).
		Update("is_default", false).Error
}
