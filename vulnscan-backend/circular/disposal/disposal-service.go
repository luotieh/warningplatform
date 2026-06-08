package disposal

import (
	"fmt"
	"time"
	"vulnscan-backend/circular/paging"
	"vulnscan-backend/circular/scope"
	"vulnscan-backend/model"

	disposalContract "vulnscan-backend/circular/disposal/disposal-contract"
	distributeContract "vulnscan-backend/circular/distribute/distribute-contract"
	inputContract "vulnscan-backend/circular/input/input-contract"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type serviceDisposal struct {
	db *db.DB
}

func NewServiceDisposal(database *db.DB) *serviceDisposal {
	return &serviceDisposal{db: database}
}

func (s *serviceDisposal) session() (*gorm.DB, error) {
	return s.db.GetDBSession()
}

func (s *serviceDisposal) List(c *gin.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error) {
	var items []inputContract.ListResp
	currentOrganize := scope.GetOrganize(c)

	sess, err := s.session()
	if err != nil {
		return 0, nil, err
	}

	tx := sess.WithContext(c).Model(&model.Circular{}).
		Joins("INNER JOIN circular_organize_status ON circular_organize_status.circular_id = circulars.id AND circular_organize_status.organize = ? AND circular_organize_status.status = ?", currentOrganize, model.CircularToBeProcessed)

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return 0, nil, err
	}

	page, size := paging.Normalize(req.Page, req.Size)
	if err := tx.Offset((page - 1) * size).Limit(size).Order("circulars.created_at DESC").Find(&items).Error; err != nil {
		return 0, nil, err
	}

	return count, items, nil
}

func (s *serviceDisposal) Dispose(c *gin.Context, id string, actor scope.Actor, req disposalContract.DisposalCondition) error {
	sess, err := s.session()
	if err != nil {
		return err
	}

	currentOrganize := scope.GetOrganize(c)

	var circular model.Circular
	if err := sess.Where("id = ?", id).First(&circular).Error; err != nil {
		return fmt.Errorf("通报不存在: id=%s", id)
	}

	var orgStatus model.CircularOrganizeStatus
	if err := sess.WithContext(c).Where("circular_id = ? AND organize = ?",
		id, currentOrganize).First(&orgStatus).Error; err != nil {
		return fmt.Errorf("当前组织不在待处置状态: circular_id=%s, organize=%s", id, currentOrganize)
	}

	disposeEvt := model.CircularOrgEvtDispose

	var dist model.CircularDistribution
	if err := sess.WithContext(c).Where("circular_id = ? AND target_organize = ?", id, currentOrganize).
		Order("depth desc").First(&dist).Error; err != nil {
		return fmt.Errorf("未找到派发记录: circular_id=%s, organize=%s", id, currentOrganize)
	}

	now := time.Now()
	if dist.ProcessingDeadline != "" {
		if parse, err := time.Parse("2006-01-02 15:04:05", dist.ProcessingDeadline); err == nil && now.After(parse) {
			disposeEvt = model.CircularOrgEvtTimeout
		}
	}

	newOrgStatus, err := model.CircularOrgSM.Apply(orgStatus.Status, disposeEvt)
	if err != nil {
		return err
	}

	return sess.WithContext(c).Transaction(func(session *gorm.DB) error {
		disposal := model.CircularDisposal{
			Circular: id, CurrentOrganize: currentOrganize, TargetOrganize: dist.CurrentOrganize,
			DisposalQuestion: req.DisposalQuestion, DisposalResult: req.DisposalResult,
		}
		disposal.Id = ulid.GenerateID()
		disposal.CreatedBy = actor.ID
		disposal.CreatedAt = now
		if err := session.Create(&disposal).Error; err != nil {
			return err
		}

		disposalDataValue, _ := req.DisposalData.Value()
		if err := session.Model(&model.Circular{}).Where("id = ?", id).Updates(map[string]interface{}{
			"disposal_organize": currentOrganize, "disposal_data": disposalDataValue,
		}).Error; err != nil {
			return err
		}

		if err := session.Model(&model.CircularOrganizeStatus{}).
			Where("circular_id = ? AND organize = ?", id, currentOrganize).
			Update("status", newOrgStatus).Error; err != nil {
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
			if err := session.Model(&model.CircularOrganizeStatus{}).
				Where("circular_id = ? AND organize = ?", id, parentOrganize).
				Update("status", model.CircularToBeReviewed).Error; err != nil {
				return err
			}
		}

		opLog := model.BuildCircularOperationLog(id, model.CircularOpDisposal, actor.ID, actor.Name, "处置完成", currentOrganize, map[string]interface{}{
			"disposal_result": req.DisposalResult, "disposal_question": req.DisposalQuestion, "new_status": string(newOrgStatus),
		})
		return session.Create(&opLog).Error
	})
}

func (s *serviceDisposal) Redistribute(c *gin.Context, req distributeContract.RedistributeReq, actor scope.Actor) error {
	sess, err := s.session()
	if err != nil {
		return err
	}

	currentOrganize := scope.GetOrganize(c)

	var circular model.Circular
	if err := sess.Where("id = ?", req.CircularId).First(&circular).Error; err != nil {
		return fmt.Errorf("通报不存在: id=%s", req.CircularId)
	}

	var orgStatus model.CircularOrganizeStatus
	if err := sess.WithContext(c).Where("circular_id = ? AND organize = ?",
		req.CircularId, currentOrganize).First(&orgStatus).Error; err != nil {
		return fmt.Errorf("当前组织不在待处置状态: circular_id=%s, organize=%s", req.CircularId, currentOrganize)
	}

	if _, err := model.CircularOrgSM.Apply(orgStatus.Status, model.CircularOrgEvtRedistribute); err != nil {
		return err
	}

	var parentDist model.CircularDistribution
	if err := sess.WithContext(c).Where("circular_id = ? AND target_organize = ?", req.CircularId, currentOrganize).
		Order("depth desc").First(&parentDist).Error; err != nil {
		return fmt.Errorf("未找到上级派发记录: circular_id=%s, organize=%s", req.CircularId, currentOrganize)
	}

	now := time.Now()
	newDepth := parentDist.Depth + 1

	return sess.WithContext(c).Transaction(func(session *gorm.DB) error {
		distributionId := ulid.GenerateID()
		dist := model.CircularDistribution{
			CircularId: circular.Code, CurrentOrganize: currentOrganize, TargetOrganize: req.TargetOrganize,
			ProcessingDeadline: parentDist.ProcessingDeadline, Requirements: parentDist.Requirements,
			Depth: newDepth, ParentDistributionId: parentDist.Id,
		}
		dist.Id = distributionId
		dist.CreatedAt = now
		dist.CreatedBy = actor.ID
		if err := session.Create(&dist).Error; err != nil {
			return err
		}

		closures := []model.CircularDistributionClosure{
			{Ancestor: distributionId, Descendant: distributionId, Distance: 0},
		}

		var parentClosures []model.CircularDistributionClosure
		if err := session.Where("descendant = ?", parentDist.Id).Find(&parentClosures).Error; err != nil {
			return err
		}
		for _, pc := range parentClosures {
			closures = append(closures, model.CircularDistributionClosure{
				Ancestor: pc.Ancestor, Descendant: distributionId, Distance: pc.Distance + 1,
			})
		}

		if err := session.Create(&closures).Error; err != nil {
			return err
		}

		if err := session.Model(&model.CircularOrganizeStatus{}).
			Where("circular_id = ? AND organize = ?", req.CircularId, currentOrganize).
			Update("status", model.CircularRedistributed).Error; err != nil {
			return err
		}

		targetOrg := model.CircularOrganizeStatus{
			CircularId: circular.Code, DistributionId: distributionId,
			Organize: req.TargetOrganize, Status: model.CircularToBeProcessed,
		}
		targetOrg.CreatedAt = now
		targetOrg.UpdatedAt = now
		if err := session.Create(&targetOrg).Error; err != nil {
			return err
		}

		opLog := model.BuildCircularOperationLog(circular.Code, model.CircularOpRedistribute, actor.ID, actor.Name, "转派成功", req.TargetOrganize, map[string]interface{}{
			"current_organize": currentOrganize, "target_organize": req.TargetOrganize, "depth": newDepth,
		})
		return session.Create(&opLog).Error
	})
}
