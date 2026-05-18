package distribute

import (
	"encoding/json"
	"fmt"
	"time"
	"vulnscan-backend/circular/paging"
	"vulnscan-backend/circular/scope"
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

func (s *serviceDistribute) List(c *gin.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error) {
	var items []inputContract.ListResp
	org := scope.GetOrganize(c)

	sess := s.session()
	tx := sess.WithContext(c).Model(&model.Circular{}).Where("status = ? AND organize = ?", model.CircularToBeDistributed, org)

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

func (s *serviceDistribute) Distribute(c *gin.Context, req distributeContract.DistributeReq, updatedBy string) error {
	sess := s.session()

	var circular model.Circular
	if err := sess.Where("id = ?", req.CircularId).First(&circular).Error; err != nil {
		return fmt.Errorf("通报不存在")
	}

	if _, err := model.CircularSM.Apply(circular.Status, model.CircularEvtDistribute); err != nil {
		return err
	}

	var tmp model.DynamicFormTemplate
	var tmpSchemaStr string
	if req.DisposalTemplate != "" {
		if err := sess.Where("id = ?", req.DisposalTemplate).First(&tmp).Error; err != nil {
			return fmt.Errorf("处置模板不存在")
		}
		schemaBytes, _ := json.Marshal(tmp.Schema)
		tmpSchemaStr = string(schemaBytes)
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
			updateData["disposal_data"] = tmpSchemaStr
			updateData["disposal_template_history_id"] = tmp.CurrentVersionID
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
			DisposalData:       tmpSchemaStr,
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
