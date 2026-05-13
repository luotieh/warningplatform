package formdesign

import (
	"errors"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type ServiceFormDesign struct {
	db *db.DB
}

func NewServiceFormDesign(database *db.DB) *ServiceFormDesign {
	return &ServiceFormDesign{db: database}
}

func (s *ServiceFormDesign) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *ServiceFormDesign) ListTemplates(query templateListReq) ([]model.DynamicFormTemplate, int64, error) {
	page, size := normalizePage(query.Page, query.PageSize)
	tx := s.session().Model(&model.DynamicFormTemplate{})
	if query.Keyword != "" {
		like := "%" + query.Keyword + "%"
		tx = tx.Where("name LIKE ? OR code LIKE ? OR description LIKE ?", like, like, like)
	}
	if query.Business != "" {
		tx = tx.Where("business = ?", query.Business)
	}
	if query.ObjectType != "" {
		tx = tx.Where("object_type = ?", query.ObjectType)
	}
	if query.Enabled != "" {
		tx = tx.Where("enabled = ?", query.Enabled != "false")
	}

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}
	var items []model.DynamicFormTemplate
	if err := tx.Order("business ASC, object_type ASC, updated_at DESC").
		Offset((page - 1) * size).
		Limit(size).
		Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, count, nil
}

func (s *ServiceFormDesign) GetTemplateWithEditableVersion(id string) (model.DynamicFormTemplate, error) {
	var item model.DynamicFormTemplate
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return item, err
	}
	var version model.DynamicFormTemplateVersion
	if item.DraftVersionID != "" {
		if err := s.session().First(&version, "id = ?", item.DraftVersionID).Error; err == nil {
			item.Schema = version.Schema
			item.Options = version.Options
			item.Version = version.Version
			return item, nil
		}
	}
	if item.CurrentVersionID != "" {
		if err := s.session().First(&version, "id = ?", item.CurrentVersionID).Error; err == nil {
			item.Schema = version.Schema
			item.Options = version.Options
			item.Version = version.Version
		}
	}
	return item, nil
}

func (s *ServiceFormDesign) CreateTemplate(req templateSaveReq, userID string) (model.DynamicFormTemplate, error) {
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
		CreatedBy:   userID,
		UpdatedBy:   userID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.session().Transaction(func(tx *gorm.DB) error {
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
			CreatedBy:   userID,
			UpdatedBy:   userID,
			PublishedBy: userID,
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
		return model.DynamicFormTemplate{}, err
	}
	return s.GetTemplateWithEditableVersion(item.ID)
}

func (s *ServiceFormDesign) UpdateTemplate(id string, req templateSaveReq, userID string) error {
	now := time.Now()
	return s.session().Transaction(func(tx *gorm.DB) error {
		var item model.DynamicFormTemplate
		if err := tx.First(&item, "id = ?", id).Error; err != nil {
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
			"updated_by":  userID,
			"updated_at":  now,
		}
		if req.Code != "" {
			updates["code"] = req.Code
		}
		if req.Enabled != nil {
			updates["enabled"] = *req.Enabled
		}
		if err := tx.Model(&model.DynamicFormTemplate{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return err
		}
		if req.Schema != nil || req.Options != nil {
			draft, err := s.ensureDraftVersion(tx, item, userID)
			if err != nil {
				return err
			}
			versionUpdates := map[string]any{
				"updated_by": userID,
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
	})
}

func (s *ServiceFormDesign) DeleteTemplate(id string) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&model.DynamicFormTemplateVersion{}, "template_id = ?", id).Error; err != nil {
			return err
		}
		return tx.Delete(&model.DynamicFormTemplate{}, "id = ?", id).Error
	})
}

// PLACEHOLDER_REMAINING_METHODS

func (s *ServiceFormDesign) ListVersions(templateID string) ([]model.DynamicFormTemplateVersion, error) {
	var items []model.DynamicFormTemplateVersion
	if err := s.session().Where("template_id = ?", templateID).Order("version DESC, updated_at DESC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (s *ServiceFormDesign) GetVersion(templateID, versionID string) (*model.DynamicFormTemplateVersion, error) {
	var item model.DynamicFormTemplateVersion
	if err := s.session().First(&item, "id = ? AND template_id = ?", versionID, templateID).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ServiceFormDesign) SaveDraft(templateID string, req versionSaveReq, userID string) (string, error) {
	var draftID string
	err := s.session().Transaction(func(tx *gorm.DB) error {
		var item model.DynamicFormTemplate
		if err := tx.First(&item, "id = ?", templateID).Error; err != nil {
			return err
		}
		draft, err := s.ensureDraftVersion(tx, item, userID)
		if err != nil {
			return err
		}
		draftID = draft.ID
		return tx.Model(&model.DynamicFormTemplateVersion{}).Where("id = ?", draft.ID).Updates(map[string]any{
			"schema":     req.Schema,
			"options":    req.Options,
			"change_log": req.ChangeLog,
			"updated_by": userID,
			"updated_at": time.Now(),
		}).Error
	})
	return draftID, err
}

func (s *ServiceFormDesign) CreateDraft(templateID, userID string) (model.DynamicFormTemplateVersion, error) {
	var draft model.DynamicFormTemplateVersion
	err := s.session().Transaction(func(tx *gorm.DB) error {
		var item model.DynamicFormTemplate
		if err := tx.First(&item, "id = ?", templateID).Error; err != nil {
			return err
		}
		var err error
		draft, err = s.ensureDraftVersion(tx, item, userID)
		return err
	})
	return draft, err
}

func (s *ServiceFormDesign) PublishDraft(templateID string, req versionSaveReq, userID string) (model.DynamicFormTemplateVersion, error) {
	var published model.DynamicFormTemplateVersion
	now := time.Now()
	err := s.session().Transaction(func(tx *gorm.DB) error {
		var item model.DynamicFormTemplate
		if err := tx.First(&item, "id = ?", templateID).Error; err != nil {
			return err
		}
		draft, err := s.ensureDraftVersion(tx, item, userID)
		if err != nil {
			return err
		}
		updates := map[string]any{
			"status":       formVersionPublished,
			"schema":       req.Schema,
			"options":      req.Options,
			"change_log":   req.ChangeLog,
			"published_by": userID,
			"published_at": &now,
			"updated_by":   userID,
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
			"updated_by":         userID,
			"updated_at":         now,
		}).Error
	})
	return published, err
}

func (s *ServiceFormDesign) ListSubmissions(query submissionListReq) ([]model.DynamicFormSubmission, int64, error) {
	page, size := normalizePage(query.Page, query.PageSize)
	tx := s.session().Model(&model.DynamicFormSubmission{})
	if query.TemplateID != "" {
		tx = tx.Where("template_id = ?", query.TemplateID)
	}
	if query.Business != "" {
		tx = tx.Where("business = ?", query.Business)
	}
	if query.ObjectID != "" {
		tx = tx.Where("object_id = ?", query.ObjectID)
	}
	if query.ObjectType != "" {
		tx = tx.Where("object_type = ?", query.ObjectType)
	}
	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}
	var items []model.DynamicFormSubmission
	if err := tx.Order("updated_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, count, nil
}

type SubmissionResult struct {
	ID                string `json:"id"`
	TemplateVersionID string `json:"template_version_id"`
}

func (s *ServiceFormDesign) GetSubmission(id string) (*model.DynamicFormSubmission, *model.DynamicFormTemplateVersion, error) {
	var item model.DynamicFormSubmission
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return nil, nil, err
	}
	var version model.DynamicFormTemplateVersion
	if item.TemplateVersionID != "" {
		_ = s.session().First(&version, "id = ?", item.TemplateVersionID).Error
	}
	return &item, &version, nil
}

func (s *ServiceFormDesign) SaveSubmission(req submissionSaveReq, userID string) (*SubmissionResult, error) {
	now := time.Now()
	versionID, versionNumber, err := s.resolveSubmissionVersion(req.TemplateID, req.TemplateVersionID)
	if err != nil {
		return nil, err
	}

	var existing model.DynamicFormSubmission
	err = s.session().Where("template_id = ? AND business = ? AND object_id = ?", req.TemplateID, req.Business, req.ObjectID).First(&existing).Error
	if err == nil {
		if existing.TemplateVersionID != "" {
			versionID = existing.TemplateVersionID
			versionNumber = firstPositive(existing.Version, versionNumber)
		}
		if err := s.session().Model(&model.DynamicFormSubmission{}).Where("id = ?", existing.ID).Updates(map[string]any{
			"template_version_id": versionID,
			"object_type":         req.ObjectType,
			"form_data":           req.FormData,
			"version":             firstPositive(req.Version, versionNumber, existing.Version),
			"updated_by":          userID,
			"updated_at":          now,
		}).Error; err != nil {
			return nil, err
		}
		return &SubmissionResult{ID: existing.ID, TemplateVersionID: versionID}, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
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
		CreatedBy:         userID,
		UpdatedBy:         userID,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.session().Create(&item).Error; err != nil {
		return nil, err
	}
	return &SubmissionResult{ID: item.ID, TemplateVersionID: versionID}, nil
}

func (s *ServiceFormDesign) DeleteSubmission(id string) error {
	return s.session().Delete(&model.DynamicFormSubmission{}, "id = ?", id).Error
}

// Private helpers

func (s *ServiceFormDesign) ensureDraftVersion(tx *gorm.DB, item model.DynamicFormTemplate, userID string) (model.DynamicFormTemplateVersion, error) {
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

func (s *ServiceFormDesign) resolveSubmissionVersion(templateID, versionID string) (string, int, error) {
	if versionID != "" {
		var version model.DynamicFormTemplateVersion
		if err := s.session().First(&version, "id = ? AND template_id = ?", versionID, templateID).Error; err != nil {
			return "", 1, err
		}
		return version.ID, version.Version, nil
	}
	var item model.DynamicFormTemplate
	if err := s.session().First(&item, "id = ?", templateID).Error; err != nil {
		return "", 1, err
	}
	if item.CurrentVersionID == "" {
		return "", firstPositive(item.Version, 1), nil
	}
	var version model.DynamicFormTemplateVersion
	if err := s.session().First(&version, "id = ?", item.CurrentVersionID).Error; err != nil {
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
