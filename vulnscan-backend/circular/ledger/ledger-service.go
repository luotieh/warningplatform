package ledger

import (
	"context"
	"fmt"
	"vulnscan-backend/model"

	inputContract "vulnscan-backend/circular/input/input-contract"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceLedger struct {
	db *db.DB
}

func NewServiceLedger(database *db.DB) *serviceLedger {
	return &serviceLedger{db: database}
}

func (s *serviceLedger) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceLedger) List(ctx context.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error) {
	var items []inputContract.ListResp

	sess := s.session()
	tx := sess.WithContext(ctx).Model(&model.Circular{}).Where("status = ?", model.CircularCompleted)

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return 0, nil, err
	}

	page, size := normalizePage(req.Page, req.Size)
	if err := tx.Offset((page - 1) * size).Limit(size).Order("created_at DESC").Find(&items).Error; err != nil {
		return 0, nil, err
	}

	return count, items, nil
}

func (s *serviceLedger) Detail(ctx context.Context, id string) (*inputContract.InputDetailResp, error) {
	if id == "" {
		return nil, fmt.Errorf("id不能为空")
	}

	sess := s.session()
	var circular model.Circular
	if err := sess.WithContext(ctx).Where("id = ?", id).First(&circular).Error; err != nil {
		return nil, fmt.Errorf("通报不存在")
	}
	if circular.Status != model.CircularCompleted {
		return nil, fmt.Errorf("该通报尚未完成，无法查看台账详情")
	}

	result := &inputContract.InputDetailResp{Circular: circular}

	sess.WithContext(ctx).Where("circular_id = ?", circular.Code).Find(&result.OrganizeStatusList)
	sess.WithContext(ctx).Where("circular_id = ?", circular.Code).Find(&result.Distributions)
	sess.WithContext(ctx).Where("circular = ?", circular.Id).Find(&result.Disposals)
	sess.WithContext(ctx).Where("circular_id = ?", circular.Code).Find(&result.Reviews)

	return result, nil
}

func normalizePage(page, size int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 20
	}
	return page, size
}
