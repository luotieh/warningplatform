package sitemonitor

import (
	"fmt"
	"log/slog"
	"time"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// CleanupConfig 执行记录自动清理配置。
type CleanupConfig struct {
	Enabled       bool `json:"enabled"`
	RetainDays    int  `json:"retain_days"`
	RetainPerTask int  `json:"retain_per_task"`
}

// DefaultCleanupConfig 返回默认清理配置。
func DefaultCleanupConfig() CleanupConfig {
	return CleanupConfig{
		Enabled:       true,
		RetainDays:    30,
		RetainPerTask: 100,
	}
}

// CleanupOldExecutions 清理过期的无问题执行记录。
// 规则：只清理 has_issue=false 的记录，同时满足两个条件才删除：
//  1. created_at 超过 retainDays 天
//  2. 该 path_task+dimension 组合的总无问题记录数超过 retainPerTask 条
//
// 有问题的记录（has_issue=true）永远不会被清理。
func CleanupOldExecutions(db *gorm.DB, cfg CleanupConfig) (int64, error) {
	if !cfg.Enabled {
		return 0, nil
	}
	if cfg.RetainDays <= 0 {
		cfg.RetainDays = 30
	}
	if cfg.RetainPerTask <= 0 {
		cfg.RetainPerTask = 100
	}

	cutoff := time.Now().AddDate(0, 0, -cfg.RetainDays)

	type taskDim struct {
		PathTaskID string
		TargetID   string
		Dimension  string
		Cnt        int64
	}
	var overflows []taskDim

	// 找出超过保留上限的 (path_task_id/target_id, dimension) 组合
	err := db.Model(&model.MonitorExecution{}).
		Select("path_task_id, target_id, dimension, COUNT(*) as cnt").
		Where("has_issue = ? AND created_at < ?", false, cutoff).
		Group("path_task_id, target_id, dimension").
		Having("cnt > 0").
		Scan(&overflows).Error
	if err != nil {
		return 0, fmt.Errorf("scan overflow groups: %w", err)
	}

	if len(overflows) == 0 {
		return 0, nil
	}

	var totalDeleted int64
	for _, td := range overflows {
		// 计算该组合的全部无问题记录数
		var totalNoIssue int64
		scope := db.Model(&model.MonitorExecution{}).Where("dimension = ? AND has_issue = ?", td.Dimension, false)
		if td.PathTaskID != "" {
			scope = scope.Where("path_task_id = ?", td.PathTaskID)
		} else {
			scope = scope.Where("target_id = ? AND (path_task_id IS NULL OR path_task_id = '')", td.TargetID)
		}
		scope.Count(&totalNoIssue)

		if totalNoIssue <= int64(cfg.RetainPerTask) {
			continue
		}

		// 找到要保留的第 N 条记录的时间戳
		var keepBoundary model.MonitorExecution
		keepScope := db.Model(&model.MonitorExecution{}).
			Where("dimension = ? AND has_issue = ?", td.Dimension, false)
		if td.PathTaskID != "" {
			keepScope = keepScope.Where("path_task_id = ?", td.PathTaskID)
		} else {
			keepScope = keepScope.Where("target_id = ? AND (path_task_id IS NULL OR path_task_id = '')", td.TargetID)
		}
		if err := keepScope.Order("created_at DESC").Offset(cfg.RetainPerTask - 1).Limit(1).First(&keepBoundary).Error; err != nil {
			continue
		}

		// 删除在保留边界之前、且超过保留天数的记录
		delScope := db.Where("dimension = ? AND has_issue = ? AND created_at < ? AND created_at < ?",
			td.Dimension, false, keepBoundary.CreatedAt, cutoff)
		if td.PathTaskID != "" {
			delScope = delScope.Where("path_task_id = ?", td.PathTaskID)
		} else {
			delScope = delScope.Where("target_id = ? AND (path_task_id IS NULL OR path_task_id = '')", td.TargetID)
		}

		result := delScope.Delete(&model.MonitorExecution{})
		totalDeleted += result.RowsAffected
	}

	if totalDeleted > 0 {
		slog.Info("[Cleanup] 已清理过期无问题执行记录",
			"deleted", totalDeleted,
			"retain_days", cfg.RetainDays,
			"retain_per_task", cfg.RetainPerTask,
		)
	}

	return totalDeleted, nil
}
