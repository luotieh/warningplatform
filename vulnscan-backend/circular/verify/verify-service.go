package verify

import (
	"context"
	"fmt"
	"vulnscan-backend/model"

	inputContract "vulnscan-backend/circular/input/input-contract"
	verifyContract "vulnscan-backend/circular/verify/verify-contract"

	"code.yt-security.com/public/core/v2/db"
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

func (s *serviceVerify) List(ctx context.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error) {
	var items []inputContract.ListResp

	sess := s.session()
	tx := sess.WithContext(ctx).Model(&model.Circular{}).Where("status = ?", model.CircularToBeVerified)

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return 0, nil, err
	}

	page, size := normalizePage(req.Page, req.Size)
	offset := (page - 1) * size
	if err := tx.Offset(offset).Limit(size).Order("created_at DESC").Find(&items).Error; err != nil {
		return 0, nil, err
	}

	return count, items, nil
}

func (s *serviceVerify) Verify(ctx context.Context, req verifyContract.VerifyReq, updatedBy string) error {
	if len(req.CircularIds) == 0 {
		return fmt.Errorf("没有需要核验的通报")
	}

	sess := s.session()
	var circulars []model.Circular
	if err := sess.WithContext(ctx).Where("id IN ?", req.CircularIds).Find(&circulars).Error; err != nil {
		return err
	}
	if len(circulars) == 0 {
		return fmt.Errorf("未找到对应的通报")
	}

	var targetStatus model.CircularStatus
	if req.Result == "pass" {
		targetStatus = model.CircularToBeDistributed
	} else {
		targetStatus = model.CircularRejected
	}

	return sess.WithContext(ctx).Transaction(func(session *gorm.DB) error {
		for _, circular := range circulars {
			if circular.Status != model.CircularToBeVerified {
				return fmt.Errorf("通报 %s 的状态异常", circular.Title)
			}

			if err := session.Model(&model.Circular{}).Where("id = ?", circular.Id).
				Updates(map[string]interface{}{"status": targetStatus, "updated_by": updatedBy}).Error; err != nil {
				return err
			}

			var opType model.CircularOperationType
			var opResult string
			if req.Result == "pass" {
				opType = model.CircularOpVerifyPass
				opResult = "核验通过"
			} else {
				opType = model.CircularOpVerifyReject
				opResult = "核验驳回"
			}
			opLog := model.BuildCircularOperationLog(circular.Code, opType, updatedBy, opResult, "", map[string]interface{}{
				"title": circular.Title, "result": req.Result,
			})
			if err := session.Create(&opLog).Error; err != nil {
				return err
			}
		}
		return nil
	})
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
