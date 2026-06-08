package assetmgr

import (
	ac "vulnscan-backend/assetmgr/assetmgr-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

type serviceVerify struct {
	db *db.DB
}

func NewServiceVerify(database *db.DB) *serviceVerify {
	return &serviceVerify{db: database}
}

func (s *serviceVerify) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceVerify) List(req ac.VerifyListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.AssetVerify, int64, error) {
	var items []model.AssetVerify
	var count int64

	q := s.session().Model(&model.AssetVerify{}).Scopes(scopes...)
	if req.AssetID != "" {
		q = q.Where("asset_id = ?", req.AssetID)
	}
	if req.Status != "" {
		q = q.Where("review_status = ?", req.Status)
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

func (s *serviceVerify) Submit(item *model.AssetVerify) error {
	if item.ID == "" {
		item.ID = ulid.GenerateID()
	}
	item.ReviewStatus = model.ReviewPending
	return s.session().Create(item).Error
}

func (s *serviceVerify) Review(id string, status, remark, reviewer string) error {
	return s.session().Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.AssetVerify{}).Where("id = ?", id).Updates(map[string]interface{}{
			"review_status": status,
			"review_remark": remark,
			"review_by":     reviewer,
		}).Error; err != nil {
			return err
		}

		if status == model.ReviewApproved {
			var v model.AssetVerify
			if err := tx.Where("id = ?", id).First(&v).Error; err != nil {
				return err
			}
			return tx.Model(&model.Asset{}).Where("id = ?", v.AssetID).
				Update("review_status", model.ReviewApproved).Error
		}
		return nil
	})
}

var _ ac.ServiceVerify = (*serviceVerify)(nil)
