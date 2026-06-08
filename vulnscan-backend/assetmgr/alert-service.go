package assetmgr

import (
	"time"

	ac "vulnscan-backend/assetmgr/assetmgr-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

type serviceAlert struct {
	db *db.DB
}

func NewServiceAlert(database *db.DB) *serviceAlert {
	return &serviceAlert{db: database}
}

func (s *serviceAlert) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceAlert) List(req ac.AlertListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Alert, int64, error) {
	var items []model.Alert
	var count int64

	q := s.session().Model(&model.Alert{}).Scopes(scopes...)
	if req.AssetID != "" {
		q = q.Where("asset_id = ?", req.AssetID)
	}
	if req.Status != "" {
		q = q.Where("status = ?", req.Status)
	}
	if req.Severity != "" {
		q = q.Where("severity = ?", req.Severity)
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
	err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error
	return items, count, err
}

func (s *serviceAlert) Create(item *model.Alert) error {
	if item.ID == "" {
		item.ID = ulid.GenerateID()
	}
	return s.session().Create(item).Error
}

func (s *serviceAlert) Ack(id string, ackedBy string) error {
	now := time.Now()
	return s.session().Model(&model.Alert{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":   model.AlertAcked,
		"acked_by": ackedBy,
		"acked_at": &now,
	}).Error
}

func (s *serviceAlert) Resolve(id string) error {
	now := time.Now()
	return s.session().Model(&model.Alert{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":      model.AlertResolved,
		"resolved_at": &now,
	}).Error
}

var _ ac.ServiceAlert = (*serviceAlert)(nil)
