package formdesign

import (
	"context"
	"fmt"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// circularInputBusinesses 通报录入模板可用的业务标识（历史迁移用 circular，前端创建多用 incident）。
var circularInputBusinesses = []string{"circular", "incident", "general", "通用"}

// ResolveCircularInputTemplate 解析通报录入默认表单模板（事件流转、手工录入等共用）。
func ResolveCircularInputTemplate(sess *gorm.DB, ctx context.Context) (model.DynamicFormTemplate, error) {
	if sess == nil {
		return model.DynamicFormTemplate{}, fmt.Errorf("database session is nil")
	}
	db := sess.WithContext(ctx)

	type attempt struct {
		businesses  []string
		objectType  string // 空表示不按 object_type 过滤
		defaultOnly bool
	}

	attempts := []attempt{
		{businesses: circularInputBusinesses, objectType: "input", defaultOnly: true},
		{businesses: circularInputBusinesses, objectType: "input", defaultOnly: false},
		{businesses: circularInputBusinesses, objectType: "", defaultOnly: true},
		{businesses: circularInputBusinesses, objectType: "", defaultOnly: false},
	}

	for _, a := range attempts {
		var item model.DynamicFormTemplate
		tx := db.Model(&model.DynamicFormTemplate{}).
			Where("enabled = ?", true).
			Where("business IN ?", a.businesses)
		if a.objectType != "" {
			tx = tx.Where("object_type = ? OR object_type = '' OR object_type IS NULL", a.objectType)
		}
		if a.defaultOnly {
			tx = tx.Where("is_default = ?", true)
		}
		if err := tx.Order("is_default DESC, updated_at DESC").First(&item).Error; err == nil {
			return item, nil
		}
	}

	// 兜底：任意已启用的非资产类录入模板
	var fallback model.DynamicFormTemplate
	if err := db.Model(&model.DynamicFormTemplate{}).
		Where("enabled = ?", true).
		Where("business != ?", "asset").
		Where("object_type = ? OR object_type = '' OR object_type IS NULL", "input").
		Order("is_default DESC, updated_at DESC").
		First(&fallback).Error; err == nil {
		return fallback, nil
	}

	return model.DynamicFormTemplate{}, fmt.Errorf("未找到录入模板，请先创建录入模板")
}
