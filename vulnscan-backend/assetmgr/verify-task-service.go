package assetmgr

import (
	"errors"
	"fmt"
	"time"

	ac "vulnscan-backend/assetmgr/assetmgr-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

type serviceVerifyTask struct {
	db *db.DB
}

func NewServiceVerifyTask(database *db.DB) *serviceVerifyTask {
	return &serviceVerifyTask{db: database}
}

func (s *serviceVerifyTask) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceVerifyTask) ListTasks(req ac.VerifyTaskListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]ac.VerifyTaskResp, int64, error) {
	var items []ac.VerifyTaskResp
	var count int64

	q := s.session().Table((&model.AssetVerifyTask{}).TableName() + " AS t").
		Select("t.*, a.name AS asset_name, a.address, a.type AS asset_type, a.data_number").
		Joins("LEFT JOIN " + (&model.Asset{}).TableName() + " AS a ON a.id = t.asset_id").
		Scopes(scopes...)
	if req.AssetID != "" {
		q = q.Where("t.asset_id = ?", req.AssetID)
	}
	if req.Status != "" {
		q = q.Where("t.status = ?", req.Status)
	}
	if req.OwnerOrganizeID != "" {
		q = q.Where("t.owner_organize_id = ?", req.OwnerOrganizeID)
	}
	if req.CurrentOrganizeID != "" {
		q = q.Where("t.current_organize_id = ?", req.CurrentOrganizeID)
	}
	if req.SourceType != "" {
		q = q.Where("t.source_type = ?", req.SourceType)
	}
	if req.Keyword != "" {
		q = q.Where("a.name LIKE ? OR a.address LIKE ? OR a.data_number LIKE ?", "%"+req.Keyword+"%", "%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}

	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}
	page, size := normalizeVerifyTaskPage(req.Page, req.PageSize)
	err := q.Order("t.updated_at DESC").
		Offset((page - 1) * size).
		Limit(size).
		Find(&items).Error
	return items, count, err
}

func (s *serviceVerifyTask) CreateTasks(req ac.VerifyTaskCreateReq, operator, organizeID string) ([]model.AssetVerifyTask, error) {
	if len(req.AssetIDs) == 0 {
		return nil, errors.New("asset ids cannot be empty")
	}
	if req.SourceType == "" {
		req.SourceType = string(model.DataSourceManual)
	}
	if req.BatchID == "" {
		req.BatchID = ulid.GenerateID()
	}

	var created []model.AssetVerifyTask
	err := s.session().Transaction(func(tx *gorm.DB) error {
		var assets []model.Asset
		if err := tx.Where("id IN ?", req.AssetIDs).Find(&assets).Error; err != nil {
			return err
		}
		if len(assets) == 0 {
			return gorm.ErrRecordNotFound
		}

		for _, asset := range assets {
			var existing model.AssetVerifyTask
			err := tx.Where("asset_id = ? AND status <> ?", asset.ID, model.AssetVerifyTaskArchived).First(&existing).Error
			if err == nil {
				created = append(created, existing)
				continue
			}
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}

			targetOrganizeID := req.TargetOrganizeID
			if targetOrganizeID == "" {
				targetOrganizeID = asset.OrganizeID
			}
			status := model.AssetVerifyTaskPendingDispatch
			selfDispatch := false
			if targetOrganizeID != "" {
				if targetOrganizeID == organizeID {
					status = model.AssetVerifyTaskPendingVerify
					selfDispatch = true
				} else {
					status = model.AssetVerifyTaskPendingReceive
				}
			}

			now := time.Now()
			task := model.AssetVerifyTask{
				ID:                ulid.GenerateID(),
				AssetID:           asset.ID,
				BatchID:           req.BatchID,
				SourceType:        req.SourceType,
				Status:            status,
				OwnerOrganizeID:   asset.OrganizeID,
				CurrentOrganizeID: targetOrganizeID,
				FromOrganizeID:    organizeID,
				TargetOrganizeID:  targetOrganizeID,
				ConstructionOrgID: asset.ConstructionOrgID,
				OperationOrgID:    asset.OperationOrgID,
				Remark:            req.Remark,
				CreatedBy:         operator,
				UpdatedBy:         operator,
				CreatedAt:         now,
				UpdatedAt:         now,
			}
			if err := tx.Create(&task).Error; err != nil {
				return err
			}
			if err := s.writeTaskLog(tx, task, model.AssetVerifyActionCreate, "", string(status), operator, req.Remark); err != nil {
				return err
			}
			if selfDispatch {
				if err := s.writeTaskLog(tx, task, model.AssetVerifyActionDispatch, "", string(model.AssetVerifyTaskPendingVerify), operator, req.Remark); err != nil {
					return err
				}
				if err := s.writeTaskLog(tx, task, model.AssetVerifyActionReceive, string(model.AssetVerifyTaskPendingVerify), string(model.AssetVerifyTaskPendingVerify), operator, "本单位自动接收"); err != nil {
					return err
				}
			} else if status == model.AssetVerifyTaskPendingReceive {
				if err := s.writeTaskLog(tx, task, model.AssetVerifyActionDispatch, "", string(status), operator, req.Remark); err != nil {
					return err
				}
			}
			created = append(created, task)
		}
		return nil
	})
	return created, err
}

var deletableStatuses = map[model.AssetVerifyTaskStatus]bool{
	model.AssetVerifyTaskPendingDispatch: true,
	model.AssetVerifyTaskPendingReceive:  true,
	model.AssetVerifyTaskRejected:        true,
	model.AssetVerifyTaskReturned:        true,
}

func (s *serviceVerifyTask) Delete(id, operator string) error {
	if id == "" {
		return errors.New("task id cannot be empty")
	}
	return s.session().Transaction(func(tx *gorm.DB) error {
		var task model.AssetVerifyTask
		if err := tx.First(&task, "id = ?", id).Error; err != nil {
			return err
		}
		if !deletableStatuses[task.Status] {
			return fmt.Errorf("状态为「%s」的任务不允许删除", task.Status)
		}
		if err := tx.Where("task_id = ?", id).Delete(&model.AssetVerifyOplog{}).Error; err != nil {
			return err
		}
		return tx.Delete(&task).Error
	})
}

func (s *serviceVerifyTask) Receive(id, operator, organizeID, remark string) error {
	return s.updateTask(id, operator, remark, func(tx *gorm.DB, task *model.AssetVerifyTask) error {
		if task.Status != model.AssetVerifyTaskPendingReceive && task.Status != model.AssetVerifyTaskForwarded {
			return fmt.Errorf("task status %s cannot receive", task.Status)
		}
		from := string(task.Status)
		task.Status = model.AssetVerifyTaskPendingVerify
		if organizeID != "" {
			task.CurrentOrganizeID = organizeID
		}
		return s.saveTaskWithLog(tx, task, model.AssetVerifyActionReceive, from, operator, remark)
	})
}

func (s *serviceVerifyTask) Confirm(id, operator, remark string) error {
	return s.updateTask(id, operator, remark, func(tx *gorm.DB, task *model.AssetVerifyTask) error {
		if task.Status != model.AssetVerifyTaskPendingVerify {
			return fmt.Errorf("task status %s cannot confirm", task.Status)
		}
		confirmedOrganizeID := task.OwnerOrganizeID
		if confirmedOrganizeID == "" {
			confirmedOrganizeID = task.CurrentOrganizeID
		}
		if confirmedOrganizeID == "" {
			confirmedOrganizeID = task.TargetOrganizeID
		}
		from := string(task.Status)
		task.Status = model.AssetVerifyTaskConfirmed
		task.OwnerOrganizeID = confirmedOrganizeID
		task.VerifyResult = model.AssetVerifyResultConfirmed
		if err := s.saveTaskWithLog(tx, task, model.AssetVerifyActionConfirm, from, operator, remark); err != nil {
			return err
		}
		return tx.Model(&model.Asset{}).Where("id = ?", task.AssetID).Updates(map[string]interface{}{
			"review_status":   model.ReviewApproved,
			"lifecycle_state": model.LifecycleConfirmed,
			"organize_id":     confirmedOrganizeID,
			"updated_by":      operator,
			"updated_at":      time.Now(),
		}).Error
	})
}

func (s *serviceVerifyTask) Reject(id, operator, reason, remark string) error {
	return s.updateTask(id, operator, remark, func(tx *gorm.DB, task *model.AssetVerifyTask) error {
		if task.Status != model.AssetVerifyTaskPendingVerify && task.Status != model.AssetVerifyTaskPendingReceive {
			return fmt.Errorf("task status %s cannot reject", task.Status)
		}
		from := string(task.Status)
		task.Status = model.AssetVerifyTaskRejected
		task.VerifyResult = model.AssetVerifyResultNotConfirmed
		task.RejectReason = reason
		if reason != "" && remark == "" {
			remark = reason
		}
		if err := s.saveTaskWithLog(tx, task, model.AssetVerifyActionReject, from, operator, remark); err != nil {
			return err
		}
		return tx.Model(&model.Asset{}).Where("id = ?", task.AssetID).Updates(map[string]interface{}{
			"review_status": model.ReviewRejected,
			"updated_by":    operator,
			"updated_at":    time.Now(),
		}).Error
	})
}

func (s *serviceVerifyTask) Forward(id, targetOrganizeID, operator, remark string) error {
	if targetOrganizeID == "" {
		return errors.New("target organize id cannot be empty")
	}
	return s.updateTask(id, operator, remark, func(tx *gorm.DB, task *model.AssetVerifyTask) error {
		if task.Status != model.AssetVerifyTaskPendingDispatch && task.Status != model.AssetVerifyTaskPendingReceive && task.Status != model.AssetVerifyTaskPendingVerify {
			return fmt.Errorf("task status %s cannot forward", task.Status)
		}
		from := string(task.Status)
		action := model.AssetVerifyActionForward
		task.Status = model.AssetVerifyTaskForwarded
		if from == model.AssetVerifyTaskPendingDispatch {
			action = model.AssetVerifyActionDispatch
			task.Status = model.AssetVerifyTaskPendingReceive
		}
		task.FromOrganizeID = task.CurrentOrganizeID
		task.TargetOrganizeID = targetOrganizeID
		task.CurrentOrganizeID = targetOrganizeID
		return s.saveTaskWithLog(tx, task, action, from, operator, remark)
	})
}

func (s *serviceVerifyTask) Return(id, operator, remark string) error {
	return s.updateTask(id, operator, remark, func(tx *gorm.DB, task *model.AssetVerifyTask) error {
		if task.Status != model.AssetVerifyTaskPendingReceive && task.Status != model.AssetVerifyTaskPendingVerify && task.Status != model.AssetVerifyTaskForwarded {
			return fmt.Errorf("task status %s cannot return", task.Status)
		}
		from := string(task.Status)
		task.Status = model.AssetVerifyTaskReturned
		return s.saveTaskWithLog(tx, task, model.AssetVerifyActionReturn, from, operator, remark)
	})
}

func (s *serviceVerifyTask) Archive(id, operator, remark string) error {
	return s.updateTask(id, operator, remark, func(tx *gorm.DB, task *model.AssetVerifyTask) error {
		if task.Status != model.AssetVerifyTaskConfirmed && task.Status != model.AssetVerifyTaskRejected && task.Status != model.AssetVerifyTaskReturned {
			return fmt.Errorf("task status %s cannot archive", task.Status)
		}
		from := string(task.Status)
		now := time.Now()
		task.Status = model.AssetVerifyTaskArchived
		task.ArchivedAt = &now
		if err := s.saveTaskWithLog(tx, task, model.AssetVerifyActionArchive, from, operator, remark); err != nil {
			return err
		}
		return s.createArchiveSnapshot(tx, *task, operator, now)
	})
}

func (s *serviceVerifyTask) Reactivate(id, operator, remark string) error {
	return s.updateTask(id, operator, remark, func(tx *gorm.DB, task *model.AssetVerifyTask) error {
		if task.Status != model.AssetVerifyTaskArchived && task.Status != model.AssetVerifyTaskReturned && task.Status != model.AssetVerifyTaskRejected {
			return fmt.Errorf("task status %s cannot reactivate", task.Status)
		}
		from := string(task.Status)
		task.Status = model.AssetVerifyTaskPendingReceive
		task.ArchivedAt = nil
		return s.saveTaskWithLog(tx, task, model.AssetVerifyActionReactivate, from, operator, remark)
	})
}

func (s *serviceVerifyTask) ListLogs(req ac.VerifyTaskLogsReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.AssetVerifyOplog, int64, error) {
	var items []model.AssetVerifyOplog
	var count int64
	q := s.session().Model(&model.AssetVerifyOplog{}).Scopes(scopes...)
	if req.TaskID != "" {
		q = q.Where("task_id = ?", req.TaskID)
	}
	if req.AssetID != "" {
		q = q.Where("asset_id = ?", req.AssetID)
	}
	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}
	page, size := normalizeVerifyTaskPage(req.Page, req.PageSize)
	err := q.Order("created_at ASC, id ASC").
		Offset((page - 1) * size).
		Limit(size).
		Find(&items).Error
	return items, count, err
}

func (s *serviceVerifyTask) ListArchives(req ac.ArchiveListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.AssetArchiveSnapshot, int64, error) {
	var items []model.AssetArchiveSnapshot
	var count int64
	q := s.session().Model(&model.AssetArchiveSnapshot{}).Scopes(scopes...)
	if req.AssetID != "" {
		q = q.Where("asset_id = ?", req.AssetID)
	}
	if req.OrganizeID != "" {
		q = q.Where("organize_id = ?", req.OrganizeID)
	}
	if req.BatchID != "" {
		q = q.Where("batch_id = ?", req.BatchID)
	}
	if req.Keyword != "" {
		q = q.Where("asset_name LIKE ? OR address LIKE ?", "%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}
	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}
	page, size := normalizeVerifyTaskPage(req.Page, req.PageSize)
	err := q.Order("archived_at DESC").
		Offset((page - 1) * size).
		Limit(size).
		Find(&items).Error
	return items, count, err
}

func (s *serviceVerifyTask) GetArchive(id string) (*model.AssetArchiveSnapshot, error) {
	var item model.AssetArchiveSnapshot
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *serviceVerifyTask) updateTask(id, operator, remark string, apply func(*gorm.DB, *model.AssetVerifyTask) error) error {
	if id == "" {
		return errors.New("task id cannot be empty")
	}
	return s.session().Transaction(func(tx *gorm.DB) error {
		var task model.AssetVerifyTask
		if err := tx.First(&task, "id = ?", id).Error; err != nil {
			return err
		}
		return apply(tx, &task)
	})
}

func (s *serviceVerifyTask) saveTaskWithLog(tx *gorm.DB, task *model.AssetVerifyTask, action model.AssetVerifyTaskAction, fromStatus, operator, remark string) error {
	task.UpdatedBy = operator
	task.UpdatedAt = time.Now()
	if err := tx.Save(task).Error; err != nil {
		return err
	}
	return s.writeTaskLog(tx, *task, action, fromStatus, string(task.Status), operator, remark)
}

func (s *serviceVerifyTask) writeTaskLog(tx *gorm.DB, task model.AssetVerifyTask, action model.AssetVerifyTaskAction, fromStatus, toStatus, operator, remark string) error {
	return tx.Create(&model.AssetVerifyOplog{
		TaskID:           task.ID,
		AssetID:          task.AssetID,
		Action:           action,
		FromStatus:       fromStatus,
		ToStatus:         toStatus,
		FromOrganizeID:   task.FromOrganizeID,
		TargetOrganizeID: task.TargetOrganizeID,
		Operator:         operator,
		Remark:           remark,
		CreatedAt:        time.Now(),
	}).Error
}

func (s *serviceVerifyTask) createArchiveSnapshot(tx *gorm.DB, task model.AssetVerifyTask, operator string, archivedAt time.Time) error {
	var existing model.AssetArchiveSnapshot
	err := tx.Where("task_id = ?", task.ID).First(&existing).Error
	if err == nil {
		return tx.Model(&model.AssetArchiveSnapshot{}).Where("id = ?", existing.ID).Updates(map[string]interface{}{
			"status":      task.Status,
			"archived_by": operator,
			"archived_at": archivedAt,
		}).Error
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	var asset model.Asset
	if err := tx.First(&asset, "id = ?", task.AssetID).Error; err != nil {
		return err
	}
	return tx.Create(&model.AssetArchiveSnapshot{
		ID:         ulid.GenerateID(),
		TaskID:     task.ID,
		AssetID:    task.AssetID,
		BatchID:    task.BatchID,
		OrganizeID: asset.OrganizeID,
		AssetName:  asset.Name,
		Address:    asset.Address,
		Status:     string(task.Status),
		Snapshot: model.JSONMap{
			"asset": asset,
			"task":  task,
		},
		ArchivedBy: operator,
		ArchivedAt: archivedAt,
		CreatedAt:  time.Now(),
	}).Error
}

func normalizeVerifyTaskPage(page, size int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 20
	}
	return page, size
}

var _ ac.ServiceVerifyTask = (*serviceVerifyTask)(nil)
