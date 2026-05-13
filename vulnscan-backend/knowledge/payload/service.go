package payload

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

func (s *Service) ListPayloads(query *PayloadQuery) ([]model.VulnPayload, int64, error) {
	var items []model.VulnPayload
	var total int64

	q := s.db.Model(&model.VulnPayload{}).Unscoped()

	if query.Category != "" {
		q = q.Where("category = ?", query.Category)
	}
	if query.Type != "" {
		q = q.Where("type = ?", query.Type)
	}
	if query.Enabled != nil {
		q = q.Where("enabled = ?", *query.Enabled)
	}
	if query.Keyword != "" {
		kw := "%" + query.Keyword + "%"
		q = q.Where("name LIKE ? OR value LIKE ? OR description LIKE ?", kw, kw, kw)
	}

	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (query.Page - 1) * query.PageSize
	if err := q.Order("category ASC, sort_order ASC, id ASC").
		Offset(offset).Limit(query.PageSize).Find(&items).Error; err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

func (s *Service) GetPayloadByID(id uint) (*model.VulnPayload, error) {
	var item model.VulnPayload
	if err := s.db.Unscoped().First(&item, id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *Service) CreatePayload(item *model.VulnPayload) error {
	return s.db.Create(item).Error
}

func (s *Service) UpdatePayload(id uint, updates map[string]any) error {
	return s.db.Model(&model.VulnPayload{}).Where("id = ?", id).Updates(updates).Error
}

func (s *Service) DeletePayload(id uint) error {
	return s.db.Delete(&model.VulnPayload{}, id).Error
}

func (s *Service) BatchCreatePayloads(items []model.VulnPayload) error {
	return s.db.CreateInBatches(items, 100).Error
}

func (s *Service) ListPatterns(query *PatternQuery) ([]model.VulnPayloadPattern, int64, error) {
	var items []model.VulnPayloadPattern
	var total int64

	q := s.db.Model(&model.VulnPayloadPattern{}).Unscoped()

	if query.Category != "" {
		q = q.Where("category = ?", query.Category)
	}
	if query.Enabled != nil {
		q = q.Where("enabled = ?", *query.Enabled)
	}
	if query.Keyword != "" {
		kw := "%" + query.Keyword + "%"
		q = q.Where("name LIKE ? OR pattern LIKE ? OR description LIKE ?", kw, kw, kw)
	}

	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (query.Page - 1) * query.PageSize
	if err := q.Order("category ASC, id ASC").
		Offset(offset).Limit(query.PageSize).Find(&items).Error; err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

func (s *Service) GetPatternByID(id uint) (*model.VulnPayloadPattern, error) {
	var item model.VulnPayloadPattern
	if err := s.db.Unscoped().First(&item, id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *Service) CreatePattern(item *model.VulnPayloadPattern) error {
	return s.db.Create(item).Error
}

func (s *Service) UpdatePattern(id uint, updates map[string]any) error {
	return s.db.Model(&model.VulnPayloadPattern{}).Where("id = ?", id).Updates(updates).Error
}

func (s *Service) DeletePattern(id uint) error {
	return s.db.Delete(&model.VulnPayloadPattern{}, id).Error
}

func (s *Service) BatchCreatePatterns(items []model.VulnPayloadPattern) error {
	return s.db.CreateInBatches(items, 100).Error
}

func (s *Service) ListConfigs(query *ConfigQuery) ([]model.VulnPayloadConfig, error) {
	var items []model.VulnPayloadConfig

	q := s.db.Model(&model.VulnPayloadConfig{})

	if query.Category != "" {
		q = q.Where("category = ?", query.Category)
	}
	if query.Enabled != nil {
		q = q.Where("enabled = ?", *query.Enabled)
	}

	if err := q.Order("category ASC, config_key ASC").Find(&items).Error; err != nil {
		return nil, err
	}

	return items, nil
}

func (s *Service) GetConfigByID(id uint) (*model.VulnPayloadConfig, error) {
	var item model.VulnPayloadConfig
	if err := s.db.First(&item, id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *Service) CreateConfig(item *model.VulnPayloadConfig) error {
	return s.db.Create(item).Error
}

func (s *Service) UpdateConfig(id uint, updates map[string]any) error {
	return s.db.Model(&model.VulnPayloadConfig{}).Where("id = ?", id).Updates(updates).Error
}

func (s *Service) DeleteConfig(id uint) error {
	return s.db.Delete(&model.VulnPayloadConfig{}, id).Error
}

func (s *Service) GetCategories() ([]string, error) {
	var categories []string
	if err := s.db.Model(&model.VulnPayload{}).
		Select("DISTINCT category").
		Order("category ASC").
		Pluck("category", &categories).Error; err != nil {
		return nil, err
	}
	return categories, nil
}

func (s *Service) ReloadPayloads(loader interface{}) error {
	type Reloader interface {
		Reload() error
	}
	if r, ok := loader.(Reloader); ok {
		return r.Reload()
	}
	return nil
}
