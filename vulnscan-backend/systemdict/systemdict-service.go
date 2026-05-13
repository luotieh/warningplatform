package systemdict

import (
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ServiceSystemDict struct {
	db *db.DB
}

func NewServiceSystemDict(database *db.DB) *ServiceSystemDict {
	return &ServiceSystemDict{db: database}
}

func (s *ServiceSystemDict) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *ServiceSystemDict) List(query dictListReq) ([]model.SystemDict, int64, error) {
	var items []model.SystemDict
	var count int64

	tx := s.session().Model(&model.SystemDict{})
	if query.Keyword != "" {
		tx = tx.Where("id LIKE ? OR name LIKE ?", "%"+query.Keyword+"%", "%"+query.Keyword+"%")
	}
	if query.Category != "" {
		tx = tx.Where("category = ?", query.Category)
	}

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	if err := tx.Order("category ASC, id ASC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&items).Error; err != nil {
		return nil, 0, err
	}

	return items, count, nil
}

func (s *ServiceSystemDict) GetByID(id string) (*model.SystemDict, []model.SystemDictItem, error) {
	var item model.SystemDict
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return nil, nil, err
	}
	var children []model.SystemDictItem
	if err := s.session().Where("dict_id = ?", id).Order("sort ASC, created_at ASC").Find(&children).Error; err != nil {
		return nil, nil, err
	}
	return &item, children, nil
}

func (s *ServiceSystemDict) Create(req dictCreateReq) (string, error) {
	if req.ID == "" {
		req.ID = qulid.GenerateID()
	}
	now := time.Now()
	err := s.session().Transaction(func(tx *gorm.DB) error {
		dict := model.SystemDict{
			ID:          req.ID,
			Name:        req.Name,
			Category:    req.Category,
			Description: req.Description,
			ItemCount:   int64(len(req.Items)),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := tx.Create(&dict).Error; err != nil {
			return err
		}
		return s.createItems(tx, req.ID, req.Items)
	})
	return req.ID, err
}

func (s *ServiceSystemDict) Update(id string, updates map[string]any) error {
	return s.session().Model(&model.SystemDict{}).Where("id = ?", id).Updates(updates).Error
}

func (s *ServiceSystemDict) Delete(id string) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("dict_id = ?", id).Delete(&model.SystemDictItem{}).Error; err != nil {
			return err
		}
		return tx.Delete(&model.SystemDict{}, "id = ?", id).Error
	})
}

func (s *ServiceSystemDict) ListItems(dictID string, enabledOnly bool) ([]model.SystemDictItem, error) {
	tx := s.session().Model(&model.SystemDictItem{})
	if dictID != "" {
		tx = tx.Where("dict_id = ?", dictID)
	}
	if enabledOnly {
		tx = tx.Where("enabled = ?", true)
	}
	var items []model.SystemDictItem
	if err := tx.Order("sort ASC, created_at ASC").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (s *ServiceSystemDict) AddItems(dictID string, inputs []dictItemInput) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		if err := s.createItems(tx, dictID, inputs); err != nil {
			return err
		}
		return s.refreshItemCount(tx, dictID)
	})
}

func (s *ServiceSystemDict) UpdateItem(dictID string, req dictItemInput) error {
	updates := map[string]any{
		"label":      req.Label,
		"value":      req.Value,
		"sort":       req.Sort,
		"remark":     req.Remark,
		"updated_at": time.Now(),
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	return s.session().Model(&model.SystemDictItem{}).
		Where("dict_id = ? AND id = ?", dictID, req.ID).
		Updates(updates).Error
}

func (s *ServiceSystemDict) DeleteItems(dictID string, ids []string) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("dict_id = ? AND id IN ?", dictID, ids).Delete(&model.SystemDictItem{}).Error; err != nil {
			return err
		}
		return s.refreshItemCount(tx, dictID)
	})
}

func (s *ServiceSystemDict) SeedDefaults() {
	defaults := defaultDicts()
	for _, d := range defaults {
		itemCount := int64(len(d.Items))
		dict := model.SystemDict{
			ID:          d.ID,
			Name:        d.Name,
			Category:    d.Category,
			Description: d.Description,
			ItemCount:   itemCount,
		}
		if err := s.session().Clauses(clause.OnConflict{DoNothing: true}).Create(&dict).Error; err != nil {
			continue
		}
		for i, item := range d.Items {
			enabled := true
			s.session().Clauses(clause.OnConflict{DoNothing: true}).Create(&model.SystemDictItem{
				ID:      d.ID + "_" + item.Value,
				DictID:  d.ID,
				Label:   item.Label,
				Value:   item.Value,
				Sort:    i + 1,
				Enabled: enabled,
			})
		}
		_ = s.refreshItemCount(s.session(), d.ID)
	}
}

func (s *ServiceSystemDict) createItems(tx *gorm.DB, dictID string, inputs []dictItemInput) error {
	if len(inputs) == 0 {
		return nil
	}
	now := time.Now()
	items := make([]model.SystemDictItem, 0, len(inputs))
	for i, input := range inputs {
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		sort := input.Sort
		if sort == 0 {
			sort = i + 1
		}
		items = append(items, model.SystemDictItem{
			ID:        firstNonEmpty(input.ID, qulid.GenerateID()),
			DictID:    dictID,
			Label:     input.Label,
			Value:     input.Value,
			Sort:      sort,
			Enabled:   enabled,
			Remark:    input.Remark,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return tx.Create(&items).Error
}

func (s *ServiceSystemDict) refreshItemCount(tx *gorm.DB, dictID string) error {
	var count int64
	if err := tx.Model(&model.SystemDictItem{}).Where("dict_id = ?", dictID).Count(&count).Error; err != nil {
		return err
	}
	return tx.Model(&model.SystemDict{}).Where("id = ?", dictID).Updates(map[string]any{
		"item_count": count,
		"updated_at": time.Now(),
	}).Error
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
