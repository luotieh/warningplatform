package migration

import (
	"fmt"
	"log/slog"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

func init() {
	Register("005_unify_data_library", "合并 Dict + Payload 为统一数据字典", migrateToDataLibrary)
}

func migrateToDataLibrary(tx *gorm.DB) error {
	if err := tx.AutoMigrate(&model.DataLibrary{}, &model.DataLibraryEntry{}); err != nil {
		return fmt.Errorf("创建新表失败: %w", err)
	}

	if err := migrateDictionaries(tx); err != nil {
		return fmt.Errorf("迁移字典失败: %w", err)
	}

	if err := migratePayloads(tx); err != nil {
		return fmt.Errorf("迁移 payload 失败: %w", err)
	}

	if err := migratePatterns(tx); err != nil {
		return fmt.Errorf("迁移 pattern 失败: %w", err)
	}

	if err := migrateConfigs(tx); err != nil {
		return fmt.Errorf("迁移 config 失败: %w", err)
	}

	return nil
}

func migrateDictionaries(tx *gorm.DB) error {
	if !tx.Migrator().HasTable("vs_dictionary") {
		return nil
	}

	var dicts []model.Dictionary
	if err := tx.Find(&dicts).Error; err != nil {
		return err
	}

	for _, d := range dicts {
		lib := model.DataLibrary{
			Name:        d.Name,
			Type:        d.Type,
			Description: d.Description,
			EntryCount:  d.EntryCount,
			Source:      d.Source,
			Status:      d.Status,
		}
		lib.ID = d.ID
		lib.CreatedBy = d.CreatedBy
		lib.OrganizeID = d.OrganizeID
		lib.CreatedAt = d.CreatedAt
		lib.UpdatedAt = d.UpdatedAt

		if err := tx.Create(&lib).Error; err != nil {
			slog.Warn("[Migration] 跳过重复字典", "name", d.Name, "error", err)
			continue
		}
	}

	var entries []model.DictionaryEntry
	if err := tx.Find(&entries).Error; err != nil {
		return err
	}

	if len(entries) > 0 {
		batch := make([]model.DataLibraryEntry, 0, len(entries))
		for _, e := range entries {
			batch = append(batch, model.DataLibraryEntry{
				ID:        e.ID,
				LibraryID: e.DictionaryID,
				Value:     e.Value,
				Tags:      e.Tags,
				Priority:  e.Priority,
				Enabled:   true,
			})
		}
		if err := tx.CreateInBatches(batch, 500).Error; err != nil {
			return err
		}
	}

	slog.Info("[Migration] 字典迁移完成", "libraries", len(dicts), "entries", len(entries))
	return nil
}

func migratePayloads(tx *gorm.DB) error {
	if !tx.Migrator().HasTable("vuln_payloads") {
		return nil
	}

	var payloads []model.VulnPayload
	if err := tx.Where("deleted_at IS NULL").Find(&payloads).Error; err != nil {
		return err
	}

	categoryLibs := make(map[string]string)
	for _, p := range payloads {
		if _, ok := categoryLibs[p.Category]; !ok {
			lib := model.DataLibrary{
				Name:     fmt.Sprintf("Payload: %s", p.Category),
				Type:     model.DataLibTypePayload,
				Category: p.Category,
				Status:   model.DataLibStatusActive,
			}
			lib.ID = qulid.GenerateID()
			if err := tx.Create(&lib).Error; err != nil {
				return err
			}
			categoryLibs[p.Category] = lib.ID
		}
	}

	if len(payloads) > 0 {
		batch := make([]model.DataLibraryEntry, 0, len(payloads))
		for _, p := range payloads {
			meta := model.JSONMap{}
			if p.Databases != "" {
				meta["databases"] = p.Databases
			}
			if p.Expect != "" {
				meta["expect"] = p.Expect
			}
			if p.Context != "" {
				meta["context"] = p.Context
			}
			if p.Severity != "" {
				meta["severity"] = p.Severity
			}
			if p.Description != "" {
				meta["description"] = p.Description
			}
			var metaVal model.JSONMap
			if len(meta) > 0 {
				metaVal = meta
			}
			batch = append(batch, model.DataLibraryEntry{
				ID:        qulid.GenerateID(),
				LibraryID: categoryLibs[p.Category],
				Name:      p.Name,
				Value:     p.Value,
				Type:      p.Type,
				Tags:      p.Tags,
				Metadata:  metaVal,
				Priority:  p.SortOrder,
				Enabled:   p.Enabled,
			})
		}
		if err := tx.CreateInBatches(batch, 500).Error; err != nil {
			return err
		}
	}

	slog.Info("[Migration] Payload 迁移完成", "categories", len(categoryLibs), "entries", len(payloads))
	return nil
}

func migratePatterns(tx *gorm.DB) error {
	if !tx.Migrator().HasTable("vuln_payload_patterns") {
		return nil
	}

	var patterns []model.VulnPayloadPattern
	if err := tx.Where("deleted_at IS NULL").Find(&patterns).Error; err != nil {
		return err
	}

	categoryLibs := make(map[string]string)
	for _, p := range patterns {
		if _, ok := categoryLibs[p.Category]; !ok {
			lib := model.DataLibrary{
				Name:     fmt.Sprintf("Pattern: %s", p.Category),
				Type:     model.DataLibTypePattern,
				Category: p.Category,
				Status:   model.DataLibStatusActive,
			}
			lib.ID = qulid.GenerateID()
			if err := tx.Create(&lib).Error; err != nil {
				return err
			}
			categoryLibs[p.Category] = lib.ID
		}
	}

	if len(patterns) > 0 {
		batch := make([]model.DataLibraryEntry, 0, len(patterns))
		for _, p := range patterns {
			var metaVal model.JSONMap
			if p.Description != "" || p.Severity != "" {
				meta := model.JSONMap{}
				if p.Description != "" {
					meta["description"] = p.Description
				}
				if p.Severity != "" {
					meta["severity"] = p.Severity
				}
				metaVal = meta
			}
			batch = append(batch, model.DataLibraryEntry{
				ID:        qulid.GenerateID(),
				LibraryID: categoryLibs[p.Category],
				Name:      p.Name,
				Value:     p.Pattern,
				Metadata:  metaVal,
				Enabled:   p.Enabled,
			})
		}
		if err := tx.CreateInBatches(batch, 500).Error; err != nil {
			return err
		}
	}

	slog.Info("[Migration] Pattern 迁移完成", "categories", len(categoryLibs), "entries", len(patterns))
	return nil
}

func migrateConfigs(tx *gorm.DB) error {
	if !tx.Migrator().HasTable("vuln_payload_configs") {
		return nil
	}

	var configs []model.VulnPayloadConfig
	if err := tx.Where("enabled = ?", true).Find(&configs).Error; err != nil {
		return err
	}

	categoryLibs := make(map[string]string)
	for _, c := range configs {
		if _, ok := categoryLibs[c.Category]; !ok {
			lib := model.DataLibrary{
				Name:     fmt.Sprintf("Config: %s", c.Category),
				Type:     model.DataLibTypeConfig,
				Category: c.Category,
				Status:   model.DataLibStatusActive,
			}
			lib.ID = qulid.GenerateID()
			if err := tx.Create(&lib).Error; err != nil {
				return err
			}
			categoryLibs[c.Category] = lib.ID
		}
	}

	if len(configs) > 0 {
		batch := make([]model.DataLibraryEntry, 0, len(configs))
		for _, c := range configs {
			batch = append(batch, model.DataLibraryEntry{
				ID:        qulid.GenerateID(),
				LibraryID: categoryLibs[c.Category],
				Name:      c.ConfigKey,
				Value:     c.ConfigVal,
				Metadata:  model.JSONMap{"config_key": c.ConfigKey},
				Enabled:   c.Enabled,
			})
		}
		if err := tx.CreateInBatches(batch, 500).Error; err != nil {
			return err
		}
	}

	slog.Info("[Migration] Config 迁移完成", "categories", len(categoryLibs), "entries", len(configs))
	return nil
}
