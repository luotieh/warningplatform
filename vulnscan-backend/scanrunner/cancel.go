package scanrunner

import (
	"strings"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
)

var cancellableTaskStatuses = []string{
	model.TaskStatusPending,
	model.TaskStatusQueued,
	model.TaskStatusRunning,
	model.TaskStatusPaused,
	model.TaskStatusSplitting,
}

// CancelScanTask 取消本机队列/Runner 中的任务，并将数据库状态置为 cancelled（含子任务）。
func CancelScanTask(db *gorm.DB, sched *Scheduler, taskID string) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" || db == nil {
		return
	}

	var related []model.ScanTask
	_ = db.Where("id = ? OR parent_id = ?", taskID, taskID).Find(&related).Error
	seen := make(map[string]struct{}, len(related)+1)
	ids := make([]string, 0, len(related)+1)
	for _, t := range related {
		if t.ID == "" {
			continue
		}
		if _, ok := seen[t.ID]; ok {
			continue
		}
		seen[t.ID] = struct{}{}
		ids = append(ids, t.ID)
	}
	if _, ok := seen[taskID]; !ok {
		ids = append(ids, taskID)
	}

	if sched != nil {
		for _, id := range ids {
			sched.CancelTask(id)
		}
	}

	now := time.Now()
	_ = db.Model(&model.ScanTask{}).
		Where("id IN ? AND status IN ?", ids, cancellableTaskStatuses).
		Updates(map[string]interface{}{
			"status":      model.TaskStatusCancelled,
			"finished_at": &now,
			"error_msg":   "用户取消",
		}).Error
}

func taskAlreadyCancelled(db *gorm.DB, taskID string) bool {
	if db == nil || taskID == "" {
		return false
	}
	var row model.ScanTask
	if err := db.Select("status").Where("id = ?", taskID).First(&row).Error; err != nil {
		return false
	}
	return row.Status == model.TaskStatusCancelled
}
