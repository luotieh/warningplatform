package scanrunner

import (
	"gorm.io/gorm"

	sedict "code.yt-security.com/public/scanengine/dict"

	"vulnscan-backend/model"
)

// DictDataSourceAdapter implements scanengine/dict.DataSource using gorm DB.
type DictDataSourceAdapter struct {
	db *gorm.DB
}

func NewDictDataSourceAdapter(db *gorm.DB) sedict.DataSource {
	return &DictDataSourceAdapter{db: db}
}

func (a *DictDataSourceAdapter) GetByName(name string) []string {
	if a.db == nil {
		return nil
	}
	var entries []model.DataLibraryEntry
	a.db.Where("library_id IN (SELECT id FROM vs_data_library WHERE name = ? AND status = ?)", name, model.DataLibStatusActive).
		Order("priority DESC").Find(&entries)
	result := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Value != "" {
			result = append(result, e.Value)
		}
	}
	return result
}

func (a *DictDataSourceAdapter) GetByType(dictType string) []string {
	if a.db == nil {
		return nil
	}
	var entries []model.DataLibraryEntry
	a.db.Where("library_id IN (SELECT id FROM vs_data_library WHERE category = ? AND status = ?)", dictType, model.DataLibStatusActive).
		Order("priority DESC").Find(&entries)
	result := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Value != "" {
			result = append(result, e.Value)
		}
	}
	return result
}

func (a *DictDataSourceAdapter) HasEntries(dictType string) bool {
	if a.db == nil {
		return false
	}
	var count int64
	a.db.Model(&model.DataLibraryEntry{}).
		Where("library_id IN (SELECT id FROM vs_data_library WHERE category = ? AND status = ?)", dictType, model.DataLibStatusActive).
		Count(&count)
	return count > 0
}
