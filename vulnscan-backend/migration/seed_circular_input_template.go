package migration

import (
	"context"

	"vulnscan-backend/formdesign"

	"gorm.io/gorm"
)

func init() {
	Register("006_seed_circular_input_template", "初始化通报录入默认表单模板", func(tx *gorm.DB) error {
		_, err := formdesign.EnsureBuiltinCircularInputTemplate(tx, context.Background())
		return err
	})
}
