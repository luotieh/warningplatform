package verify

import (
	"context"
	"fmt"
	"vulnscan-backend/circular/paging"
	"vulnscan-backend/circular/scope"
	"vulnscan-backend/model"

	inputContract "vulnscan-backend/circular/input/input-contract"
	verifyContract "vulnscan-backend/circular/verify/verify-contract"

	"code.yt-security.com/public/core/db"
	"github.com/gin-gonic/gin"
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

func (s *serviceVerify) List(c *gin.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error) {
	var items []inputContract.ListResp
	org := scope.GetOrganize(c)

	sess := s.session()
	tx := sess.WithContext(c).Model(&model.Circular{}).Where("status = ? AND organize = ?", model.CircularToBeVerified, org)

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return 0, nil, err
	}

	page, size := paging.Normalize(req.Page, req.Size)
	offset := (page - 1) * size
	if err := tx.Offset(offset).Limit(size).Order("created_at DESC").Find(&items).Error; err != nil {
		return 0, nil, err
	}

	return count, items, nil
}

func (s *serviceVerify) Verify(ctx context.Context, req verifyContract.VerifyReq, actor scope.Actor) error {
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

	var event string
	if req.Result == "pass" {
		event = model.CircularEvtVerifyPass
	} else {
		event = model.CircularEvtVerifyReject
	}

	return sess.WithContext(ctx).Transaction(func(session *gorm.DB) error {
		for _, circular := range circulars {
			newStatus, err := model.CircularSM.Apply(circular.Status, event)
			if err != nil {
				return fmt.Errorf("通报 %s 状态异常: %w", circular.Title, err)
			}

			if err := session.Model(&model.Circular{}).Where("id = ?", circular.Id).
				Updates(map[string]interface{}{"status": newStatus, "updated_by": actor.ID}).Error; err != nil {
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
			opLog := model.BuildCircularOperationLog(circular.Code, opType, actor.ID, actor.Name, opResult, "", map[string]interface{}{
				"title": circular.Title, "result": req.Result,
			})
			if err := session.Create(&opLog).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
