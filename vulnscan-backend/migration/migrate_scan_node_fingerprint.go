package migration

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

func init() {
	Register("007_scan_node_machine_fingerprint", "扫描节点表增加 machine_fingerprint（接入防重复）", func(tx *gorm.DB) error {
		return tx.AutoMigrate(&model.Node{})
	})
}
