package distribute

import (
	"context"
	"fmt"
	"time"
	"vulnscan-backend/model"

	distributeContract "vulnscan-backend/circular/distribute/distribute-contract"
	inputContract "vulnscan-backend/circular/input/input-contract"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type serviceDistribute struct {
	db *db.DB
}

func NewServiceDistribute(database *db.DB) *serviceDistribute {
	return &serviceDistribute{db: database}
}

func (s *serviceDistribute) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceDistribute) List(ctx context.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error) {
	var items []inputContract.ListResp

	sess := s.session()
	tx := sess.WithContext(ctx).Model(&model.Circular{}).Where("status = ?", model.CircularToBeDistributed)

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

func (s *serviceDistribute) Distribute(c *gin.Context, req distributeContract.DistributeReq, updatedBy string) error {
	sess := s.session()

	var circular model.Circular
	if err := sess.Where("id = ?", req.CircularId).First(&circular).Error; err != nil {
		return fmt.Errorf("通报不存在")
	}

	if circular.Status != model.CircularToBeDistributed {
		return fmt.Errorf("通报状态错误，当前状态不允许派发")
	}

	var tmp model.CircularTemplate
	if req.DisposalTemplate != "" {
		if err := sess.Where("id = ?", req.DisposalTemplate).First(&tmp).Error; err != nil {
			return fmt.Errorf("处置模板不存在")
		}
	}

	now := time.Now()

	return sess.WithContext(c).Transaction(func(session *gorm.DB) error {
		updateData := map[string]interface{}{
			"distribution_time":   now,
			"processing_deadline": req.ProcessingDeadline,
			"status":              model.CircularInProgress,
			"updated_at":          now,
			"updated_by":          updatedBy,
		}
		if req.DisposalTemplate != "" {
			updateData["disposal_template"] = req.DisposalTemplate
			updateData["disposal_data"] = tmp.TemplateData
			updateData["disposal_template_history_id"] = tmp.TemplateHistoryLastId
		}
		if err := session.Model(&model.Circular{}).Where("id = ?", req.CircularId).Updates(updateData).Error; err != nil {
			return err
		}

		distributionId := qulid.GenerateID()
		distribution := model.CircularDistribution{
			CircularId:         circular.Code,
			CurrentOrganize:    "yt-networks-security",
			TargetOrganize:     req.TargetOrganize,
			ProcessingDeadline: req.ProcessingDeadline,
			Requirements:       req.Requirements,
			Depth:              0,
			DisposalData:       tmp.TemplateData,
		}
		distribution.Id = distributionId
		distribution.CreatedAt = now
		distribution.CreatedBy = updatedBy
		if err := session.Create(&distribution).Error; err != nil {
			return err
		}

		closure := model.CircularDistributionClosure{
			Ancestor: distributionId, Descendant: distributionId, Distance: 0,
		}
		if err := session.Create(&closure).Error; err != nil {
			return err
		}

		orgStatus := model.CircularOrganizeStatus{
			CircularId:     circular.Code,
			DistributionId: distributionId,
			Organize:       req.TargetOrganize,
			Status:         model.CircularToBeProcessed,
		}
		orgStatus.CreatedAt = now
		orgStatus.UpdatedAt = now
		if err := session.Create(&orgStatus).Error; err != nil {
			return err
		}

		opLog := model.BuildCircularOperationLog(circular.Code, model.CircularOpDistribute, updatedBy, "派发成功", req.TargetOrganize, map[string]interface{}{
			"target_organize":     req.TargetOrganize,
			"processing_deadline": req.ProcessingDeadline,
			"requirements":        req.Requirements,
			"disposal_template":   req.DisposalTemplate,
		})
		return session.Create(&opLog).Error
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
