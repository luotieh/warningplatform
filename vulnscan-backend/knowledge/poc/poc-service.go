package poc

import (
	"vulnscan-backend/knowledge/nuclei"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type PocQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Severity string `form:"severity"`
	Category string `form:"category"`
	Enabled  *bool  `form:"enabled"`
}

type ServicePoc struct {
	db    *db.DB
	store *nuclei.PocStore
}

func NewServicePoc(database *db.DB, store *nuclei.PocStore) *ServicePoc {
	return &ServicePoc{db: database, store: store}
}

func (s *ServicePoc) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

// Session 返回 GORM 会话（供 Handler 等创建 NucleiModule 等使用）。
func (s *ServicePoc) Session() *gorm.DB {
	return s.session()
}

func (s *ServicePoc) List(q PocQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.PocTemplate, int64, error) {
	tx := s.session().Model(&model.PocTemplate{}).Scopes(scopes...)
	if q.Keyword != "" {
		like := "%" + q.Keyword + "%"
		tx = tx.Where("name LIKE ? OR poc_id LIKE ? OR cve LIKE ?", like, like, like)
	}
	if q.Severity != "" {
		tx = tx.Where("severity = ?", q.Severity)
	}
	if q.Category != "" {
		tx = tx.Where("category = ?", q.Category)
	}
	if q.Enabled != nil {
		tx = tx.Where("enabled = ?", *q.Enabled)
	}

	var count int64
	tx.Count(&count)

	if q.PageSize <= 0 {
		q.PageSize = 20
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	offset := (q.Page - 1) * q.PageSize

	var items []model.PocTemplate
	err := tx.Order("created_at DESC").Offset(offset).Limit(q.PageSize).Find(&items).Error
	return items, count, err
}

func (s *ServicePoc) GetByID(id string) (*model.PocTemplate, error) {
	var item model.PocTemplate
	err := s.session().Where("id = ?", id).First(&item).Error
	return &item, err
}

func (s *ServicePoc) InvalidateCache() {
	if s.store != nil {
		s.store.Invalidate()
	}
}

func (s *ServicePoc) Create(item *model.PocTemplate) error {
	if item.ID == "" {
		item.ID = qulid.GenerateID()
	}
	return s.session().Create(item).Error
}

func (s *ServicePoc) Update(id string, updates map[string]any) error {
	err := s.session().Model(&model.PocTemplate{}).Where("id = ?", id).Updates(updates).Error
	if err == nil {
		s.store.InvalidateCache()
	}
	return err
}

func (s *ServicePoc) Delete(id string) error {
	err := s.session().Where("id = ?", id).Delete(&model.PocTemplate{}).Error
	if err == nil {
		s.store.InvalidateCache()
	}
	return err
}

func (s *ServicePoc) Toggle(id string, enabled bool) error {
	err := s.session().Model(&model.PocTemplate{}).Where("id = ?", id).Update("enabled", enabled).Error
	if err == nil {
		s.store.InvalidateCache()
	}
	return err
}

func (s *ServicePoc) ImportYAML(yaml string) (*model.PocTemplate, error) {
	return s.store.ImportFromYAML(yaml)
}

func (s *ServicePoc) ImportDir(dir string) (imported, skipped, errors int) {
	return s.store.ImportFromDir(dir)
}
