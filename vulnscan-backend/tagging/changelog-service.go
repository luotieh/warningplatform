package tagging

import (
	"vulnscan-backend/model"
	tc "vulnscan-backend/tagging/tagging-contract"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceChangeLog struct {
	db *db.DB
}

func NewServiceChangeLog(database *db.DB) *serviceChangeLog {
	return &serviceChangeLog{db: database}
}

func (s *serviceChangeLog) List(req tc.ChangeLogListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.AssetChangeLog, int64, error) {
	sess, _ := s.db.GetDBSession()
	var list []model.AssetChangeLog
	var count int64

	q := sess.Model(&model.AssetChangeLog{}).Scopes(scopes...)
	if req.AssetID != "" {
		q = q.Where("asset_id = ?", req.AssetID)
	}
	if req.ChangeType != "" {
		q = q.Where("change_type = ?", req.ChangeType)
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
	err := q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&list).Error
	return list, count, err
}

func (s *serviceChangeLog) GetByAssetID(assetID string) ([]model.AssetChangeLog, error) {
	sess, _ := s.db.GetDBSession()
	var list []model.AssetChangeLog
	err := sess.Where("asset_id = ?", assetID).Order("id DESC").Find(&list).Error
	return list, err
}

func (s *serviceChangeLog) Record(log *model.AssetChangeLog) error {
	sess, _ := s.db.GetDBSession()
	return sess.Create(log).Error
}

var _ tc.ServiceChangeLog = (*serviceChangeLog)(nil)
