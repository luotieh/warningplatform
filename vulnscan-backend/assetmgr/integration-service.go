package assetmgr

import (
	ac "vulnscan-backend/assetmgr/assetmgr-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceIntegration struct {
	db *db.DB
}

func NewServiceIntegration(database *db.DB) *serviceIntegration {
	return &serviceIntegration{db: database}
}

func (s *serviceIntegration) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceIntegration) ListSources(req ac.IntSourceListReq) ([]model.IntegrationSource, int64, error) {
	var items []model.IntegrationSource
	var count int64

	q := s.session().Model(&model.IntegrationSource{})
	if req.Module != "" {
		q = q.Where("module = ?", req.Module)
	}
	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	page, size := req.Page, req.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}
	err := q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error
	return items, count, err
}

func (s *serviceIntegration) CreateSource(item *model.IntegrationSource) error {
	return s.session().Create(item).Error
}

func (s *serviceIntegration) UpdateSource(id int64, data map[string]interface{}) error {
	return s.session().Model(&model.IntegrationSource{}).Where("id = ?", id).Updates(data).Error
}

func (s *serviceIntegration) DeleteSource(id int64) error {
	return s.session().Where("id = ?", id).Delete(&model.IntegrationSource{}).Error
}

var _ ac.ServiceIntegration = (*serviceIntegration)(nil)
