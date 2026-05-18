package migration

import (
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

func init() {
	Register("005_migrate_circular_templates", "合并通报模板到动态表单中心", func(tx *gorm.DB) error {
		if !tx.Migrator().HasTable("circular_templates") {
			return nil
		}

		type oldTemplate struct {
			Id                  string    `gorm:"column:id"`
			TemplateName        string    `gorm:"column:template_name"`
			TemplateDescription string    `gorm:"column:template_description"`
			TemplateData        string    `gorm:"column:template_data"`
			Type                string    `gorm:"column:type"`
			DefaultFlag         bool      `gorm:"column:default_flag"`
			CreatedBy           string    `gorm:"column:created_by"`
			UpdatedBy           string    `gorm:"column:updated_by"`
			CreatedAt           time.Time `gorm:"column:created_at"`
			UpdatedAt           time.Time `gorm:"column:updated_at"`
		}

		var oldTemplates []oldTemplate
		if err := tx.Table("circular_templates").Find(&oldTemplates).Error; err != nil {
			return err
		}

		if len(oldTemplates) == 0 {
			return nil
		}

		if err := tx.AutoMigrate(
			&struct {
				ID               string `gorm:"primarykey;type:varchar(36)"`
				Name             string `gorm:"type:varchar(200);not null"`
				Code             string `gorm:"type:varchar(100);not null;uniqueIndex"`
				Business         string `gorm:"type:varchar(50);not null;index"`
				ObjectType       string `gorm:"type:varchar(100);index"`
				Description      string `gorm:"type:varchar(500)"`
				Schema           string `gorm:"type:text"`
				Options          string `gorm:"type:text"`
				Version          int    `gorm:"default:1"`
				CurrentVersionID string `gorm:"type:varchar(36)"`
				DraftVersionID   string `gorm:"type:varchar(36)"`
				Enabled          bool   `gorm:"default:true"`
				IsDefault        bool   `gorm:"default:false"`
				CreatedBy        string `gorm:"type:varchar(64)"`
				UpdatedBy        string `gorm:"type:varchar(64)"`
				CreatedAt        time.Time
				UpdatedAt        time.Time
			}{}); err != nil {
			return err
		}

		for _, ot := range oldTemplates {
			versionId := qulid.GenerateID()
			newTemplate := map[string]interface{}{
				"id":                 ot.Id,
				"name":               ot.TemplateName,
				"code":               "circular_" + ot.Type + "_" + ot.Id[:8],
				"business":           "circular",
				"object_type":        ot.Type,
				"description":        ot.TemplateDescription,
				"schema":             ot.TemplateData,
				"options":            "{}",
				"version":            1,
				"current_version_id": versionId,
				"draft_version_id":   "",
				"enabled":            true,
				"is_default":         ot.DefaultFlag,
				"created_by":         ot.CreatedBy,
				"updated_by":         ot.UpdatedBy,
				"created_at":         ot.CreatedAt,
				"updated_at":         ot.UpdatedAt,
			}
			if err := tx.Table("vs_dynamic_form_template").Create(newTemplate).Error; err != nil {
				return err
			}

			version := map[string]interface{}{
				"id":          versionId,
				"template_id": ot.Id,
				"schema":      ot.TemplateData,
				"options":     "{}",
				"version":     1,
				"is_current":  true,
				"created_at":  ot.CreatedAt,
			}
			if err := tx.Table("vs_dynamic_form_template_version").Create(version).Error; err != nil {
				return err
			}
		}

		return nil
	})
}
