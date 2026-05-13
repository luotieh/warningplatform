package assetmgr

import (
	ac "vulnscan-backend/assetmgr/assetmgr-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceLifecycle struct {
	db *db.DB
}

func NewServiceLifecycle(database *db.DB) *serviceLifecycle {
	return &serviceLifecycle{db: database}
}

func (s *serviceLifecycle) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceLifecycle) ListTransitions(req ac.LifecycleListReq) ([]model.AssetLifecycle, int64, error) {
	var items []model.AssetLifecycle
	var count int64

	q := s.session().Model(&model.AssetLifecycle{})
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

func (s *serviceLifecycle) Transition(assetID, toState, operator, remark string) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		record := model.AssetLifecycle{
			AssetID:  assetID,
			ToState:  toState,
			Operator: operator,
			Remark:   remark,
		}
		return tx.Create(&record).Error
	})
}

var _ ac.ServiceLifecycle = (*serviceLifecycle)(nil)
