package scanrunner

import (
	"log/slog"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// CleanupAssetEnrichTask 资产富化任务在结束后自动删除任务记录（保留 scan_findings）。
func CleanupAssetEnrichTask(db *gorm.DB, task *model.ScanTask) {
	if db == nil || task == nil || task.Type != model.TaskTypeAssetEnrich {
		return
	}
	switch task.Status {
	case model.TaskStatusCompleted, model.TaskStatusPartial,
		model.TaskStatusFailed, model.TaskStatusCancelled:
	default:
		return
	}

	if err := db.Delete(&model.ScanTask{}, "id = ?", task.ID).Error; err != nil {
		slog.Warn("[AssetEnrich] 自动删除任务记录失败", "task_id", task.ID, "error", err)
		return
	}
	slog.Info("[AssetEnrich] 已自动删除富化任务记录", "task_id", task.ID, "status", task.Status)

	if parentID := task.ParentID; parentID != "" {
		maybeDeleteEmptyEnrichParent(db, parentID)
	}
}

func maybeDeleteEmptyEnrichParent(db *gorm.DB, parentID string) {
	var n int64
	if err := db.Model(&model.ScanTask{}).Where("parent_id = ?", parentID).Count(&n).Error; err != nil || n > 0 {
		return
	}
	var parent model.ScanTask
	if err := db.First(&parent, "id = ?", parentID).Error; err != nil {
		return
	}
	if parent.Type != model.TaskTypeAssetEnrich {
		return
	}
	if err := db.Delete(&model.ScanTask{}, "id = ?", parentID).Error; err != nil {
		slog.Warn("[AssetEnrich] 删除空父任务失败", "parent_id", parentID, "error", err)
		return
	}
	slog.Info("[AssetEnrich] 已删除无子任务的富化父任务", "parent_id", parentID)
}
