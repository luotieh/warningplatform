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
// 使用单条查询批量标记所有维度的过期 execution。
func ExpireAllStaleExecutions(db *gorm.DB) (int64, error) {
	if db == nil {
		return 0, nil
	}

	now := time.Now()
	var total int64

	// 按维度分组的超时cutoff，使用最短的超时来先找候选记录
	shortestTimeout := 3 * time.Minute
	cutoff := now.Add(-shortestTimeout)

	var candidates []model.MonitorExecution
	if err := db.Model(&model.MonitorExecution{}).
		Where("status IN ? AND created_at < ?", []string{"pending", "running"}, cutoff).
		Select("id, dimension, created_at, started_at").
		Find(&candidates).Error; err != nil {
		return 0, err
	}

	if len(candidates) == 0 {
		return 0, nil
	}

	expiredIDs := make([]string, 0)
	for _, exec := range candidates {
		timeout := StaleTimeoutForDimension(exec.Dimension)
		if now.Sub(exec.CreatedAt) >= timeout {
			expiredIDs = append(expiredIDs, exec.ID)
		}
	}

	if len(expiredIDs) == 0 {
		return 0, nil
	}

	const batchSize = 500
	for i := 0; i < len(expiredIDs); i += batchSize {
		end := i + batchSize
		if end > len(expiredIDs) {
			end = len(expiredIDs)
		}
		batch := expiredIDs[i:end]
		result := db.Model(&model.MonitorExecution{}).
			Where("id IN ?", batch).
			Updates(map[string]any{
				"status":      "failed",
				"error":       "执行超时，已自动结束",
				"finished_at": now,
				"reaped_at":   now,
			})
		total += result.RowsAffected
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

	now := time.Now()
	msg := fmt.Sprintf("执行超时（超过 %s 未完成），已自动结束", StaleTimeoutForDimension(dimension))

	result := q.Updates(map[string]any{
		"status":      "failed",
		"error":       msg,
		"finished_at": now,
		"reaped_at":   now,
	})

	return result.RowsAffected, result.Error
}
