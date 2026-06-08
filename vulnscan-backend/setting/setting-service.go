package setting

import (
	"encoding/json"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ServiceSetting struct {
	db    *db.DB
	cache sync.Map
}

func NewServiceSetting(database *db.DB) *ServiceSetting {
	svc := &ServiceSetting{db: database}
	svc.warmCache()
	return svc
}

func (s *ServiceSetting) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *ServiceSetting) warmCache() {
	var items []model.SystemSetting
	if err := s.session().Find(&items).Error; err != nil {
		slog.Error("加载系统设置缓存失败", "error", err)
		return
	}
	for _, item := range items {
		s.cache.Store(item.Key, item.Value)
	}
	slog.Info("[+] 系统设置缓存已加载", "count", len(items))
}

// Get returns the cached value for key, or fallback if not found.
func (s *ServiceSetting) Get(key, fallback string) string {
	if v, ok := s.cache.Load(key); ok {
		return v.(string)
	}
	return fallback
}

// GetInt returns the cached value as int, or fallback on miss/parse error.
func (s *ServiceSetting) GetInt(key string, fallback int) int {
	str := s.Get(key, "")
	if str == "" {
		return fallback
	}
	v, err := strconv.Atoi(str)
	if err != nil {
		return fallback
	}
	return v
}

// GetBool returns the cached value as bool, or fallback on miss/parse error.
func (s *ServiceSetting) GetBool(key string, fallback bool) bool {
	str := s.Get(key, "")
	if str == "" {
		return fallback
	}
	v, err := strconv.ParseBool(str)
	if err != nil {
		return fallback
	}
	return v
}

// GetJSON unmarshals the cached value into target.
func (s *ServiceSetting) GetJSON(key string, target interface{}) error {
	str := s.Get(key, "")
	if str == "" {
		return nil
	}
	return json.Unmarshal([]byte(str), target)
}

// ListAll returns settings optionally filtered by group.
func (s *ServiceSetting) ListAll(group string) ([]model.SystemSetting, error) {
	var items []model.SystemSetting
	tx := s.session().Model(&model.SystemSetting{})
	if group != "" {
		tx = tx.Where("`group` = ?", group)
	}
	if err := tx.Order("`group`, `key`").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// GetByKey retrieves a single setting by key.
func (s *ServiceSetting) GetByKey(key string) (*model.SystemSetting, error) {
	var item model.SystemSetting
	if err := s.session().Where("`key` = ?", key).First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

// BatchUpdate upserts multiple settings and refreshes the cache.
func (s *ServiceSetting) BatchUpdate(items []struct {
	Key   string
	Value string
}, updatedBy string) error {
	now := time.Now()
	err := s.session().Transaction(func(tx *gorm.DB) error {
		for _, item := range items {
			result := tx.Model(&model.SystemSetting{}).
				Where("`key` = ?", item.Key).
				Updates(map[string]any{
					"value":      item.Value,
					"updated_at": now,
					"updated_by": updatedBy,
				})
			if result.RowsAffected == 0 {
				if err := tx.Create(&model.SystemSetting{
					Key:       item.Key,
					Value:     item.Value,
					UpdatedAt: now,
					UpdatedBy: updatedBy,
				}).Error; err != nil {
					return err
				}
			}
			if result.Error != nil {
				return result.Error
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, item := range items {
		s.cache.Store(item.Key, item.Value)
	}
	return nil
}

// ResetGroup resets all settings in a group to their defaults.
func (s *ServiceSetting) ResetGroup(group, updatedBy string) error {
	defaults := defaultSettings()
	now := time.Now()
	err := s.session().Transaction(func(tx *gorm.DB) error {
		for _, d := range defaults {
			if d.Group != group {
				continue
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at", "updated_by"}),
			}).Create(&model.SystemSetting{
				Key:       d.Key,
				Value:     d.Value,
				Group:     d.Group,
				Label:     d.Label,
				ValueType: d.ValueType,
				UpdatedAt: now,
				UpdatedBy: updatedBy,
			}).Error; err != nil {
				return err
			}
			s.cache.Store(d.Key, d.Value)
		}
		return nil
	})
	return err
}

// SeedDefaults inserts default settings that don't already exist.
func (s *ServiceSetting) SeedDefaults() {
	defaults := defaultSettings()
	now := time.Now()
	for _, d := range defaults {
		s.session().Clauses(clause.OnConflict{DoNothing: true}).Create(&model.SystemSetting{
			Key:         d.Key,
			Value:       d.Value,
			Group:       d.Group,
			Label:       d.Label,
			Description: d.Description,
			ValueType:   d.ValueType,
			IsSecret:    d.IsSecret,
			UpdatedAt:   now,
		})
		if _, loaded := s.cache.Load(d.Key); !loaded {
			s.cache.Store(d.Key, d.Value)
		}
	}
}
