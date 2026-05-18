package systemdict

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// EnabledDictLabels 返回字典项展示名（仅 enabled=true），优先读库，无数据时用内置默认项。
func EnabledDictLabels(db *gorm.DB, dictID string) []string {
	labels, err := enabledDictLabelsFromDB(db, dictID)
	if err != nil || len(labels) == 0 {
		return DefaultDictLabels(dictID)
	}
	return labels
}

func enabledDictLabelsFromDB(db *gorm.DB, dictID string) ([]string, error) {
	if db == nil || dictID == "" {
		return nil, nil
	}
	var items []model.SystemDictItem
	if err := db.Where("dict_id = ? AND enabled = ?", dictID, true).
		Order("sort ASC, label ASC").
		Find(&items).Error; err != nil {
		return nil, err
	}
	labels := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		label := item.Label
		if label == "" {
			label = item.Value
		}
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		labels = append(labels, label)
	}
	return labels, nil
}
