package sitemonitor

import (
	"fmt"
	"time"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// StaleTimeoutForDimension 监测任务允许的最长执行时间（含排队）。
func StaleTimeoutForDimension(dimension string) time.Duration {
	switch dimension {
	case "availability", "domain_hijack":
		return 3 * time.Minute
	case "tamper":
		return 6 * time.Minute
	case "sensitive_word", "sensitive_file", "blacklink":
		return 12 * time.Minute
	default:
		return 10 * time.Minute
	}
}

// ExpireStaleExecutionsForScope 将超时未完成的 pending/running 记录标记为 failed。
func ExpireStaleExecutionsForScope(db *gorm.DB, targetID, pathTaskID, dimension string) (int64, error) {
	if db == nil || dimension == "" {
		return 0, nil
	}
	cutoff := time.Now().Add(-StaleTimeoutForDimension(dimension))
	return expireStaleExecutions(db, targetID, pathTaskID, dimension, cutoff)
}

// ExpireAllStaleExecutions 供健康检查循环调用。
func ExpireAllStaleExecutions(db *gorm.DB) (int64, error) {
	if db == nil {
		return 0, nil
	}
	var total int64
	for _, dim := range model.MonitorAllDimensions {
		cutoff := time.Now().Add(-StaleTimeoutForDimension(dim))
		n, err := expireStaleExecutions(db, "", "", dim, cutoff)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func expireStaleExecutions(db *gorm.DB, targetID, pathTaskID, dimension string, cutoff time.Time) (int64, error) {
	q := db.Model(&model.MonitorExecution{}).
		Where("dimension = ? AND status IN ?", dimension, []string{"pending", "running"}).
		Where("created_at < ?", cutoff)
	if pathTaskID != "" {
		q = q.Where("path_task_id = ?", pathTaskID)
	} else if targetID != "" {
		q = q.Where("target_id = ? AND (path_task_id IS NULL OR path_task_id = '')", targetID)
	}

	var stale []model.MonitorExecution
	if err := q.Find(&stale).Error; err != nil {
		return 0, err
	}
	if len(stale) == 0 {
		return 0, nil
	}

	now := time.Now()
	reaped := now
	msg := fmt.Sprintf("执行超时（超过 %s 未完成），已自动结束", StaleTimeoutForDimension(dimension))

	for _, exec := range stale {
		updates := map[string]any{
			"status":      "failed",
			"error":       msg,
			"finished_at": now,
			"reaped_at":   reaped,
		}
		if exec.StartedAt == nil {
			updates["started_at"] = exec.CreatedAt
		}
		if err := db.Model(&model.MonitorExecution{}).Where("id = ?", exec.ID).Updates(updates).Error; err != nil {
			return 0, err
		}
	}

	return int64(len(stale)), nil
}
