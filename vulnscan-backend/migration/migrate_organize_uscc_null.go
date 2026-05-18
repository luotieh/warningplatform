package migration

import "gorm.io/gorm"

func init() {
	Register("006_organize_uscc_null", "单位统一社会信用代码空串改为 NULL", func(tx *gorm.DB) error {
		return tx.Exec(
			`UPDATE vs_organize SET unified_social_credit_code = NULL WHERE unified_social_credit_code = ''`,
		).Error
	})
}
