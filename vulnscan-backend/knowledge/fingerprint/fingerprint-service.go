package fingerprint

import (
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

type FingerprintQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Service  string `form:"service"`
	Protocol string `form:"protocol"`
	Status   string `form:"status"`
}

type ServiceFingerprint struct {
	db *db.DB
}

func NewServiceFingerprint(database *db.DB) *ServiceFingerprint {
	return &ServiceFingerprint{db: database}
}

func (s *ServiceFingerprint) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *ServiceFingerprint) List(q FingerprintQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.ServiceFingerprint, int64, error) {
	tx := s.session().Model(&model.ServiceFingerprint{}).Scopes(scopes...)
	if q.Keyword != "" {
		like := "%" + q.Keyword + "%"
		tx = tx.Where("name LIKE ? OR service LIKE ? OR description LIKE ?", like, like, like)
	}
	if q.Service != "" {
		tx = tx.Where("service = ?", q.Service)
	}
	if q.Protocol != "" {
		tx = tx.Where("protocol = ?", q.Protocol)
	}
	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
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

	var items []model.ServiceFingerprint
	err := tx.Order("priority DESC, created_at DESC").Offset(offset).Limit(q.PageSize).Find(&items).Error
	return items, count, err
}

func (s *ServiceFingerprint) GetByID(id string) (*model.ServiceFingerprint, error) {
	var item model.ServiceFingerprint
	err := s.session().Where("id = ?", id).First(&item).Error
	return &item, err
}

func (s *ServiceFingerprint) Create(item *model.ServiceFingerprint) error {
	if item.ID == "" {
		item.ID = ulid.GenerateID()
	}
	return s.session().Create(item).Error
}

func (s *ServiceFingerprint) Update(id string, updates map[string]any) error {
	return s.session().Model(&model.ServiceFingerprint{}).Where("id = ?", id).Updates(updates).Error
}

func (s *ServiceFingerprint) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.ServiceFingerprint{}).Error
}
