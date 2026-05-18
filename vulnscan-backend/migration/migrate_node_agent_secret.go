package migration

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

func init() {
	Register("006_add_vs_nodes_agent_secret_hash", "节点表增加 agent_secret_hash（node-api 第二因子）", func(tx *gorm.DB) error {
		return tx.AutoMigrate(&model.Node{})
	})
}
