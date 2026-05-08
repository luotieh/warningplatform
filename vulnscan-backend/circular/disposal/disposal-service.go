package disposal

import (
	"fmt"
	"time"
	"vulnscan-backend/model"

	disposalContract "vulnscan-backend/circular/disposal/disposal-contract"
	distributeContract "vulnscan-backend/circular/distribute/distribute-contract"
	inputContract "vulnscan-backend/circular/input/input-contract"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type serviceDisposal struct {
	db *db.DB
}

func NewServiceDisposal(database *db.DB) *serviceDisposal {
	return &serviceDisposal{db: database}
}

func (s *serviceDisposal) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceDisposal) List(c *gin.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error) {
	var items []inputContract.ListResp

	user, _ := iamsdk.GetCurrentUser(c)
	currentOrganize := user.OrganizeID
	if currentOrganize == "" {
		currentOrganize = "yt-networks-security"
	}

	sess := s.session()

	var circularIds []string
	if err := sess.WithContext(c).Model(&model.CircularOrganizeStatus{}).
		Where("organize = ? AND status = ?", currentOrganize, model.CircularToBeProcessed).
		Pluck("circular_id", &circularIds).Error; err != nil {
		return 0, nil, err
	}
	if len(circularIds) == 0 {
		return 0, items, nil
	}

	tx := sess.WithContext(c).Model(&model.Circular{}).Where("code IN ?", circularIds)
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

func (s *serviceDisposal) Dispose(c *gin.Context, id string, updatedBy string, req disposalContract.DisposalCondition) error {
	sess := s.session()

	user, _ := iamsdk.GetCurrentUser(c)
	currentOrganize := user.OrganizeID
	if currentOrganize == "" {
		currentOrganize = "yt-networks-security"
	}

	var circular model.Circular
	if err := sess.Where("id = ?", id).First(&circular).Error; err != nil {
		return fmt.Errorf("通报不存在")
	}

	var orgStatus model.CircularOrganizeStatus
	if err := sess.WithContext(c).Where("circular_id = ? AND organize = ? AND status = ?",
		id, currentOrganize, model.CircularToBeProcessed).First(&orgStatus).Error; err != nil {
		return fmt.Errorf("当前组织不在待处置状态")
	}

	var dist model.CircularDistribution
	if err := sess.WithContext(c).Where("circular_id = ? AND target_organize = ?", id, currentOrganize).
		Order("depth desc").First(&dist).Error; err != nil {
		return fmt.Errorf("未找到派发记录")
	}

	now := time.Now()
	var isTimeout bool
	if dist.ProcessingDeadline != "" {
		if parse, err := time.Parse("2006-01-02 15:04:05", dist.ProcessingDeadline); err == nil && now.After(parse) {
			isTimeout = true
		}
	}

	return sess.WithContext(c).Transaction(func(session *gorm.DB) error {
		disposal := model.CircularDisposal{
			Circular: id, CurrentOrganize: currentOrganize, TargetOrganize: dist.CurrentOrganize,
			DisposalQuestion: req.DisposalQuestion, DisposalResult: req.DisposalResult,
		}
		disposal.Id = qulid.GenerateID()
		disposal.CreatedBy = updatedBy
		disposal.CreatedAt = now
		if err := session.Create(&disposal).Error; err != nil {
			return err
		}

		disposalDataValue, _ := req.DisposalData.Value()
		if err := session.Model(&model.Circular{}).Where("code = ?", id).Updates(map[string]interface{}{
			"disposal_organize": currentOrganize, "disposal_data": disposalDataValue,
		}).Error; err != nil {
			return err
		}

		newStatus := model.CircularDisposed
		if isTimeout {
			newStatus = model.CircularTimeOut
		}
		if err := session.Model(&model.CircularOrganizeStatus{}).
			Where("circular_id = ? AND organize = ?", id, currentOrganize).
			Update("status", newStatus).Error; err != nil {
			return err
		}

		parentOrganize := dist.CurrentOrganize
		var parentOrgStatus model.CircularOrganizeStatus
		if err := session.Where("circular_id = ? AND organize = ?", id, parentOrganize).First(&parentOrgStatus).Error; err != nil {
			parentOrgStatus = model.CircularOrganizeStatus{
				CircularId: id, DistributionId: dist.Id, Organize: parentOrganize, Status: model.CircularToBeReviewed,
			}
			parentOrgStatus.CreatedAt = now
			parentOrgStatus.UpdatedAt = now
			if err := session.Create(&parentOrgStatus).Error; err != nil {
				return err
			}
		} else {
			session.Model(&model.CircularOrganizeStatus{}).
				Where("circular_id = ? AND organize = ?", id, parentOrganize).
				Update("status", model.CircularToBeReviewed)
		}

		opLog := model.BuildCircularOperationLog(id, model.CircularOpDisposal, updatedBy, "处置完成", currentOrganize, map[string]interface{}{
			"disposal_result": req.DisposalResult, "disposal_question": req.DisposalQuestion, "is_timeout": isTimeout,
		})
		return session.Create(&opLog).Error
	})
}

func (s *serviceDisposal) Redistribute(c *gin.Context, req distributeContract.RedistributeReq, updatedBy string) error {
	sess := s.session()

	user, _ := iamsdk.GetCurrentUser(c)
	currentOrganize := user.OrganizeID
	if currentOrganize == "" {
		currentOrganize = "yt-networks-security"
	}

	var circular model.Circular
	if err := sess.Where("id = ?", req.CircularId).First(&circular).Error; err != nil {
		return fmt.Errorf("通报不存在")
	}

	var orgStatus model.CircularOrganizeStatus
	if err := sess.WithContext(c).Where("circular_id = ? AND organize = ? AND status = ?",
		req.CircularId, currentOrganize, model.CircularToBeProcessed).First(&orgStatus).Error; err != nil {
		return fmt.Errorf("当前组织不在待处置状态")
	}

	var parentDist model.CircularDistribution
	if err := sess.WithContext(c).Where("circular_id = ? AND target_organize = ?", req.CircularId, currentOrganize).
		Order("depth desc").First(&parentDist).Error; err != nil {
		return fmt.Errorf("未找到上级派发记录")
	}

	now := time.Now()
	newDepth := parentDist.Depth + 1

	return sess.WithContext(c).Transaction(func(session *gorm.DB) error {
		distributionId := qulid.GenerateID()
		dist := model.CircularDistribution{
			CircularId: circular.Code, CurrentOrganize: currentOrganize, TargetOrganize: req.TargetOrganize,
			ProcessingDeadline: parentDist.ProcessingDeadline, Requirements: parentDist.Requirements,
			Depth: newDepth, ParentDistributionId: parentDist.Id,
		}
		dist.Id = distributionId
		dist.CreatedAt = now
		dist.CreatedBy = updatedBy
		if err := session.Create(&dist).Error; err != nil {
			return err
		}

		if err := session.Create(&model.CircularDistributionClosure{
			Ancestor: distributionId, Descendant: distributionId, Distance: 0,
		}).Error; err != nil {
			return err
		}

		var parentClosures []model.CircularDistributionClosure
		session.Where("descendant = ?", parentDist.Id).Find(&parentClosures)
		for _, pc := range parentClosures {
			if err := session.Create(&model.CircularDistributionClosure{
				Ancestor: pc.Ancestor, Descendant: distributionId, Distance: pc.Distance + 1,
			}).Error; err != nil {
				return err
			}
		}

		session.Model(&model.CircularOrganizeStatus{}).
			Where("circular_id = ? AND organize = ?", req.CircularId, currentOrganize).
			Update("status", model.CircularRedistributed)

		targetOrg := model.CircularOrganizeStatus{
			CircularId: circular.Code, DistributionId: distributionId,
			Organize: req.TargetOrganize, Status: model.CircularToBeProcessed,
		}
		targetOrg.CreatedAt = now
		targetOrg.UpdatedAt = now
		if err := session.Create(&targetOrg).Error; err != nil {
			return err
		}

		opLog := model.BuildCircularOperationLog(circular.Code, model.CircularOpRedistribute, updatedBy, "转派成功", req.TargetOrganize, map[string]interface{}{
			"current_organize": currentOrganize, "target_organize": req.TargetOrganize, "depth": newDepth,
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
