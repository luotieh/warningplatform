package exclusion

import (
	exclusionContract "vulnscan-backend/exclusion/exclusion-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type serviceExclusion struct {
	db *db.DB
}

func NewServiceExclusion(database *db.DB) *serviceExclusion {
	return &serviceExclusion{db: database}
}

func (s *serviceExclusion) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *serviceExclusion) List(query exclusionContract.ExclusionQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.ScanExclusion, int64, error) {
	var items []model.ScanExclusion
	var count int64

	tx := s.session().Model(&model.ScanExclusion{}).Scopes(scopes...)

	if query.Keyword != "" {
		tx = tx.Where("name LIKE ? OR match_value LIKE ?", "%"+query.Keyword+"%", "%"+query.Keyword+"%")
	}
	if query.RuleType != "" {
		tx = tx.Where("rule_type = ?", query.RuleType)
	}
	if query.Scope != "" {
		tx = tx.Where("scope = ?", query.Scope)
	}
	if query.Enabled != nil {
		tx = tx.Where("enabled = ?", *query.Enabled)
	}

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 || query.PageSize > 100 {
		query.PageSize = 20
	}
	offset := (query.Page - 1) * query.PageSize

	if err := tx.Offset(offset).Limit(query.PageSize).Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, count, nil
}

func (s *serviceExclusion) GetByID(id string) (*model.ScanExclusion, error) {
	var item model.ScanExclusion
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *serviceExclusion) Create(item *model.ScanExclusion) error {
	if item.ID == "" {
		item.ID = qulid.GenerateID()
	}
	return s.session().Create(item).Error
}

func (s *serviceExclusion) Update(id string, updates map[string]any) error {
	return s.session().Model(&model.ScanExclusion{}).Where("id = ?", id).Updates(updates).Error
}

func (s *serviceExclusion) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.ScanExclusion{}).Error
}

func (s *serviceExclusion) Toggle(id string) error {
	var item model.ScanExclusion
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return err
	}
	return s.session().Model(&item).Update("enabled", !item.Enabled).Error
}

func (s *serviceExclusion) GetActiveRules(scopes ...string) ([]model.ScanExclusion, error) {
	var items []model.ScanExclusion
	tx := s.session().Where("enabled = ?", true)
	if len(scopes) > 0 {
		tx = tx.Where("scope IN ?", append(scopes, model.ExclusionScopeGlobal))
	}
	if err := tx.Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (s *serviceExclusion) IncrHitCount(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return s.session().Model(&model.ScanExclusion{}).Where("id IN ?", ids).
		UpdateColumn("hit_count", gorm.Expr("hit_count + 1")).Error
}
