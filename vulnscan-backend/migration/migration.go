package migration

import (
	"log/slog"
	"sort"
	"time"

	"gorm.io/gorm"
)

type MigrationRecord struct {
	ID        string    `gorm:"primarykey;type:varchar(50)"`
	Name      string    `gorm:"type:varchar(200)"`
	AppliedAt time.Time `gorm:"autoCreateTime"`
}

func (MigrationRecord) TableName() string { return "vs_migration" }

type MigrationFunc func(tx *gorm.DB) error

type migration struct {
	id   string
	name string
	fn   MigrationFunc
}

var registry []migration

func Register(id, name string, fn MigrationFunc) {
	registry = append(registry, migration{id: id, name: name, fn: fn})
}

func RunAll(db *gorm.DB) error {
	if err := db.AutoMigrate(&MigrationRecord{}); err != nil {
		return err
	}

	var applied []MigrationRecord
	db.Find(&applied)
	appliedMap := make(map[string]bool)
	for _, a := range applied {
		appliedMap[a.ID] = true
	}

	sort.Slice(registry, func(i, j int) bool {
		return registry[i].id < registry[j].id
	})

	for _, m := range registry {
		if appliedMap[m.id] {
			continue
		}

		slog.Info("[Migration] 执行迁移", "id", m.id, "name", m.name)
		if err := db.Transaction(func(tx *gorm.DB) error {
			if err := m.fn(tx); err != nil {
				return err
			}
			return tx.Create(&MigrationRecord{
				ID:   m.id,
				Name: m.name,
			}).Error
		}); err != nil {
			slog.Error("[Migration] 迁移失败", "id", m.id, "error", err)
			return err
		}
		slog.Info("[Migration] 迁移完成", "id", m.id)
	}

	return nil
}

func init() {
	Register("001_init_indexes", "创建关键索引", func(tx *gorm.DB) error {
		indexes := []string{
			"CREATE INDEX IF NOT EXISTS idx_scan_finding_task_type ON vs_scan_finding(task_id, type)",
			"CREATE INDEX IF NOT EXISTS idx_scan_finding_task_module ON vs_scan_finding(task_id, module_id)",
			"CREATE INDEX IF NOT EXISTS idx_scan_finding_target ON vs_scan_finding(target)",
			"CREATE INDEX IF NOT EXISTS idx_vulnerability_task_severity ON vs_vulnerability(task_id, severity)",
			"CREATE INDEX IF NOT EXISTS idx_vulnerability_status ON vs_vulnerability(status)",
			"CREATE INDEX IF NOT EXISTS idx_asset_host ON vs_asset(host)",
			"CREATE INDEX IF NOT EXISTS idx_scan_log_task ON vs_scan_log(task_id)",
			"CREATE INDEX IF NOT EXISTS idx_notification_user_read ON vs_notification(user_id, read)",
		}
		for _, sql := range indexes {
			if err := tx.Exec(sql).Error; err != nil {
				slog.Warn("[Migration] 索引创建跳过", "sql", sql, "error", err)
			}
		}
		return nil
	})

	Register("002_add_asset_fingerprint", "资产表增加指纹字段", func(tx *gorm.DB) error {
		columns := []struct {
			table  string
			column string
			colDef string
		}{
			{"vs_asset", "fingerprint", "VARCHAR(500) DEFAULT ''"},
			{"vs_asset", "last_scan_at", "TIMESTAMP"},
			{"vs_asset", "vuln_count", "INTEGER DEFAULT 0"},
			{"vs_asset", "risk_score", "FLOAT DEFAULT 0"},
		}
		for _, col := range columns {
			if !tx.Migrator().HasColumn(col.table, col.column) {
				tx.Exec("ALTER TABLE " + col.table + " ADD COLUMN " + col.column + " " + col.colDef)
			}
		}
		return nil
	})
}
