package review

import (
	"errors"
	"fmt"
	"time"
	"vulnscan-backend/circular/paging"
	"vulnscan-backend/circular/scope"
	"vulnscan-backend/model"

	inputContract "vulnscan-backend/circular/input/input-contract"
	reviewContract "vulnscan-backend/circular/review/review-contract"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type serviceReview struct {
	db *db.DB
}

func NewServiceReview(database *db.DB) *serviceReview {
	return &serviceReview{db: database}
}

func (s *serviceReview) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceReview) List(c *gin.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error) {
	var items []inputContract.ListResp

	user, _ := iamsdk.GetCurrentUser(c)
	currentOrganize := user.OrganizeID
	if currentOrganize == "" {
		currentOrganize = scope.DefaultOrganizeID()
	}

	sess := s.session()

	var circularIds []string
	if err := sess.WithContext(c).Model(&model.CircularOrganizeStatus{}).
		Where("organize = ? AND status = ?", currentOrganize, model.CircularToBeReviewed).
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

	page, size := paging.Normalize(req.Page, req.Size)
	if err := tx.Offset((page - 1) * size).Limit(size).Order("created_at DESC").Find(&items).Error; err != nil {
		return 0, nil, err
	}
	return count, items, nil
}

func (s *serviceReview) Review(c *gin.Context, id string, actor scope.Actor, req reviewContract.ReviewCondition) error {
	sess := s.session()
	user, _ := iamsdk.GetCurrentUser(c)
	currentOrganize := user.OrganizeID
	if currentOrganize == "" {
		currentOrganize = scope.DefaultOrganizeID()
	}

	var circular model.Circular
	if err := sess.Where("id = ?", id).First(&circular).Error; err != nil {
		return fmt.Errorf("通报不存在")
	}

	var orgStatus model.CircularOrganizeStatus
	if err := sess.WithContext(c).Where("circular_id = ? AND organize = ? AND status = ?",
		circular.Code, currentOrganize, model.CircularToBeReviewed).First(&orgStatus).Error; err != nil {
		return fmt.Errorf("当前组织不在待审核状态")
	}

	var receivedDist model.CircularDistribution
	var isTopLevel bool
	var currentDepth int

	if err := sess.WithContext(c).Where("circular_id = ? AND target_organize = ?", circular.Code, currentOrganize).
		Order("depth desc").First(&receivedDist).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		isTopLevel = true
	} else {
		currentDepth = receivedDist.Depth
		if receivedDist.CurrentOrganize == receivedDist.TargetOrganize {
			isTopLevel = true
		}
	}

	now := time.Now()

	if req.Review == "approved" {
		return s.reviewApprove(c, sess, circular, receivedDist, currentOrganize, actor, req, now, isTopLevel, currentDepth)
	}
	return s.reviewReject(c, sess, circular, currentOrganize, actor, req, now)
}

func (s *serviceReview) reviewApprove(
	c *gin.Context, sess *gorm.DB,
	circular model.Circular, receivedDist model.CircularDistribution,
	currentOrganize string,
	actor scope.Actor,
	req reviewContract.ReviewCondition,
	now time.Time, isTopLevel bool, currentDepth int,
) error {
	return sess.WithContext(c).Transaction(func(session *gorm.DB) error {
		rev := model.CircularReview{
			CircularId: circular.Code, Organize: currentOrganize, Depth: currentDepth,
			Review: "approved", Instructions: req.Instructions, Annex: req.Annex,
		}
		if !isTopLevel {
			rev.DistributionId = receivedDist.Id
		}
		rev.Id = qulid.GenerateID()
		rev.CreatedBy = actor.ID
		rev.CreatedAt = now
		if err := session.Create(&rev).Error; err != nil {
			return err
		}

		if err := session.Model(&model.CircularOrganizeStatus{}).
			Where("circular_id = ? AND organize = ?", circular.Code, currentOrganize).
			Update("status", model.CircularReviewed).Error; err != nil {
			return err
		}

		if isTopLevel {
			if err := session.Model(&model.Circular{}).Where("id = ?", circular.Id).
				Updates(map[string]interface{}{"status": model.CircularCompleted, "updated_at": now, "updated_by": actor.ID}).Error; err != nil {
				return err
			}
		} else {
			parentOrganize := receivedDist.CurrentOrganize
			var parentOrgStatus model.CircularOrganizeStatus
			if err := session.Where("circular_id = ? AND organize = ?", circular.Code, parentOrganize).
				First(&parentOrgStatus).Error; err != nil {
				po := model.CircularOrganizeStatus{
					CircularId: circular.Code, DistributionId: receivedDist.ParentDistributionId,
					Organize: parentOrganize, Status: model.CircularToBeReviewed,
				}
				po.CreatedAt = now
				po.UpdatedAt = now
				if err := session.Create(&po).Error; err != nil {
					return err
				}
			} else {
				if err := session.Model(&model.CircularOrganizeStatus{}).
					Where("circular_id = ? AND organize = ?", circular.Code, parentOrganize).
					Update("status", model.CircularToBeReviewed).Error; err != nil {
					return err
				}
			}
		}

		opLog := model.BuildCircularOperationLog(circular.Code, model.CircularOpReviewApprove, actor.ID, actor.Name, "审核通过", currentOrganize, map[string]interface{}{
			"instructions": req.Instructions, "is_top_level": isTopLevel, "depth": currentDepth,
		})
		if err := session.Create(&opLog).Error; err != nil {
			return err
		}

		if isTopLevel {
			completedLog := model.BuildCircularOperationLog(circular.Code, model.CircularOpCompleted, actor.ID, actor.Name, "已完成", "", nil)
			return session.Create(&completedLog).Error
		}
		return nil
	})
}

func (s *serviceReview) reviewReject(
	c *gin.Context, sess *gorm.DB,
	circular model.Circular,
	currentOrganize string,
	actor scope.Actor,
	req reviewContract.ReviewCondition,
	now time.Time,
) error {
	return sess.WithContext(c).Transaction(func(session *gorm.DB) error {
		rev := model.CircularReview{
			CircularId: circular.Code, Organize: currentOrganize,
			Review: "rejected", Instructions: req.Instructions, Annex: req.Annex,
		}
		rev.Id = qulid.GenerateID()
		rev.CreatedBy = actor.ID
		rev.CreatedAt = now
		if err := session.Create(&rev).Error; err != nil {
			return err
		}

		if err := session.Model(&model.CircularOrganizeStatus{}).
			Where("circular_id = ? AND organize = ?", circular.Code, currentOrganize).
			Update("status", model.CircularRejected).Error; err != nil {
			return err
		}

		var deepestDist model.CircularDistribution
		if err := session.Where("circular_id = ?", circular.Code).Order("depth desc").First(&deepestDist).Error; err != nil {
			return fmt.Errorf("未找到最末端的派发记录")
		}
		lastOrganize := deepestDist.TargetOrganize

		if err := session.Model(&model.CircularOrganizeStatus{}).
			Where("circular_id = ? AND organize = ?", circular.Code, lastOrganize).
			Update("status", model.CircularToBeProcessed).Error; err != nil {
			return err
		}

		if err := session.Model(&model.CircularOrganizeStatus{}).
			Where("circular_id = ? AND organize != ? AND organize != ? AND status = ?",
				circular.Code, currentOrganize, lastOrganize, model.CircularReviewed).
			Update("status", model.CircularRedistributed).Error; err != nil {
			return err
		}

		opLog := model.BuildCircularOperationLog(circular.Code, model.CircularOpReviewReject, actor.ID, actor.Name, "审核驳回", currentOrganize, map[string]interface{}{
			"instructions": req.Instructions, "rejected_to": lastOrganize,
		})
		return session.Create(&opLog).Error
	})
}
