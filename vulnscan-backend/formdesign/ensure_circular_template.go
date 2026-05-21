package formdesign

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

const BuiltinCircularInputTemplateCode = "builtin-circular-input-default"

// EnsureBuiltinCircularInputTemplate 在无可用模板时创建系统默认「通报录入」模板（幂等）。
func EnsureBuiltinCircularInputTemplate(sess *gorm.DB, ctx context.Context) (model.DynamicFormTemplate, error) {
	if sess == nil {
		return model.DynamicFormTemplate{}, fmt.Errorf("database session is nil")
	}
	db := sess.WithContext(ctx)

	var existing model.DynamicFormTemplate
	if err := db.Where("code = ?", BuiltinCircularInputTemplateCode).First(&existing).Error; err == nil {
		if existing.Enabled && existing.CurrentVersionID != "" {
			return existing, nil
		}
		updates := map[string]any{"enabled": true}
		if existing.CurrentVersionID == "" {
			if repaired, err := repairTemplateCurrentVersion(db, &existing); err != nil {
				return model.DynamicFormTemplate{}, err
			} else {
				return repaired, nil
			}
		}
		_ = db.Model(&model.DynamicFormTemplate{}).Where("id = ?", existing.ID).Updates(updates)
		return existing, nil
	}

	now := time.Now()
	templateID := qulid.GenerateID()
	versionID := qulid.GenerateID()
	schema := model.JSONMap{"rule": []any{}}
	options := model.JSONMap{}

	item := model.DynamicFormTemplate{
		ID:          templateID,
		Name:        "通报录入默认模板",
		Code:        BuiltinCircularInputTemplateCode,
		Business:    "circular",
		ObjectType:  "input",
		Description: "系统内置：安全事件流转通报、手工录入时自动使用；可在「表单模板」中替换为自定义模板并设为默认。",
		Schema:      schema,
		Options:     options,
		Version:     1,
		Enabled:     true,
		IsDefault:   true,
		CreatedBy:   "system",
		UpdatedBy:   "system",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	version := model.DynamicFormTemplateVersion{
		ID:          versionID,
		TemplateID:  templateID,
		Version:     1,
		Status:      formVersionPublished,
		Schema:      schema,
		Options:     options,
		ChangeLog:   "系统内置初始版本",
		CreatedBy:   "system",
		UpdatedBy:   "system",
		PublishedBy: "system",
		PublishedAt: &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		if err := clearDefault(tx, item.Business, item.ObjectType); err != nil {
			return err
		}
		if err := tx.Create(&item).Error; err != nil {
			return err
		}
		if err := tx.Create(&version).Error; err != nil {
			return err
		}
		return tx.Model(&model.DynamicFormTemplate{}).Where("id = ?", templateID).Updates(map[string]any{
			"current_version_id": versionID,
		}).Error
	})
	if err != nil {
		return model.DynamicFormTemplate{}, err
	}
	slog.Info("[formdesign] 已自动创建通报录入默认模板", "code", BuiltinCircularInputTemplateCode, "id", templateID)
	item.CurrentVersionID = versionID
	return item, nil
}

func repairTemplateCurrentVersion(db *gorm.DB, item *model.DynamicFormTemplate) (model.DynamicFormTemplate, error) {
	now := time.Now()
	versionID := qulid.GenerateID()
	schema := item.Schema
	if schema == nil {
		schema = model.JSONMap{"rule": []any{}}
	}
	options := item.Options
	if options == nil {
		options = model.JSONMap{}
	}
	version := model.DynamicFormTemplateVersion{
		ID:          versionID,
		TemplateID:  item.ID,
		Version:     firstPositive(item.Version, 1),
		Status:      formVersionPublished,
		Schema:      schema,
		Options:     options,
		ChangeLog:   "系统修复发布版本",
		CreatedBy:   "system",
		UpdatedBy:   "system",
		PublishedBy: "system",
		PublishedAt: &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.Create(&version).Error; err != nil {
		return model.DynamicFormTemplate{}, err
	}
	if err := db.Model(&model.DynamicFormTemplate{}).Where("id = ?", item.ID).Updates(map[string]any{
		"current_version_id": versionID,
		"enabled":            true,
	}).Error; err != nil {
		return model.DynamicFormTemplate{}, err
	}
	item.CurrentVersionID = versionID
	item.Enabled = true
	return *item, nil
}
