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
