package assetmgr

import (
	ac "vulnscan-backend/assetmgr/assetmgr-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceResponsible struct {
	db *db.DB
}

func NewServiceResponsible(database *db.DB) *serviceResponsible {
	return &serviceResponsible{db: database}
}

func (s *serviceResponsible) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceResponsible) List(req ac.ResponsibleListReq) ([]model.AssetResponsible, int64, error) {
	var items []model.AssetResponsible
	var count int64

	q := s.session().Model(&model.AssetResponsible{})
	if req.AssetID != "" {
		q = q.Where("asset_id = ?", req.AssetID)
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

func (s *serviceResponsible) Create(item *model.AssetResponsible) error {
	return s.session().Create(item).Error
}

func (s *serviceResponsible) Update(id int64, data map[string]interface{}) error {
	return s.session().Model(&model.AssetResponsible{}).Where("id = ?", id).Updates(data).Error
}

func (s *serviceResponsible) Delete(id int64) error {
	return s.session().Where("id = ?", id).Delete(&model.AssetResponsible{}).Error
}

var _ ac.ServiceResponsible = (*serviceResponsible)(nil)
