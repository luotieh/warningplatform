package scanrunner

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

type TaskSplitter struct {
	db               *gorm.DB
	maxTargetsPerSub int
}

func NewTaskSplitter(db *gorm.DB) *TaskSplitter {
	return &TaskSplitter{
		db:               db,
		maxTargetsPerSub: 256,
	}
}

type SubTask struct {
	ID       string   `json:"id"`
	ParentID string   `json:"parent_id"`
	Shard    string   `json:"shard"`
	Targets  []string `json:"targets"`
	Status   string   `json:"status"`
}

func (s *TaskSplitter) ShouldSplit(targets []string) bool {
	return len(targets) > s.maxTargetsPerSub
}

func (s *TaskSplitter) Split(parentTask model.ScanTask) ([]model.ScanTask, error) {
	groups := s.groupTargets(parentTask.Targets)

	var subTasks []model.ScanTask
	for i, group := range groups {
		subID := uuid.New().String()
		now := time.Now()
		sub := model.ScanTask{
			ID:           subID,
			Name:         fmt.Sprintf("%s [分片 %d/%d: %s]", parentTask.Name, i+1, len(groups), group.key),
			TemplateID:   parentTask.TemplateID,
			TemplateName: parentTask.TemplateName,
			Type:         parentTask.Type,
			Targets:      group.targets,
			Config:       parentTask.Config,
			Parameters:   stripWorkerShardSchedulingParams(parentTask.Parameters),
			Priority:     parentTask.Priority,
			Profile:      parentTask.Profile,
			ScheduleID:   parentTask.ScheduleID,
			CreatedBy:    parentTask.CreatedBy,
			OrganizeID:   parentTask.OrganizeID,
			Status:       model.TaskStatusQueued,
			TotalTargets: len(group.targets),
			ParentID:     parentTask.ID,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		subTasks = append(subTasks, sub)
	}

	if err := s.db.Model(&parentTask).Updates(map[string]interface{}{
		"status":    model.TaskStatusSplitting,
		"sub_count": len(subTasks),
	}).Error; err != nil {
		return nil, fmt.Errorf("更新父任务状态失败: %w", err)
	}

	for i := range subTasks {
		if err := s.db.Create(&subTasks[i]).Error; err != nil {
			return nil, fmt.Errorf("创建子任务 %d 失败: %w", i, err)
		}
	}

	slog.Info("[TaskSplitter] 任务已拆分",
		"parent", parentTask.ID,
		"sub_count", len(subTasks),
		"total_targets", len(parentTask.Targets),
	)

	return subTasks, nil
}

type targetGroup struct {
	key     string
	targets []string
}

func (s *TaskSplitter) groupTargets(targets []string) []targetGroup {
	groups := make(map[string][]string)

	for _, t := range targets {
		key := s.classifyTarget(t)
		groups[key] = append(groups[key], t)
	}

	var result []targetGroup
	for key, ts := range groups {
		if len(ts) <= s.maxTargetsPerSub {
			result = append(result, targetGroup{key: key, targets: ts})
			continue
		}

		for i := 0; i < len(ts); i += s.maxTargetsPerSub {
			end := i + s.maxTargetsPerSub
			if end > len(ts) {
				end = len(ts)
			}
			shardKey := fmt.Sprintf("%s/%c", key, rune('A'+i/s.maxTargetsPerSub))
			result = append(result, targetGroup{key: shardKey, targets: ts[i:end]})
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return len(result[i].targets) > len(result[j].targets)
	})

	return result
}

func (s *TaskSplitter) classifyTarget(t string) string {
	if _, cidr, err := net.ParseCIDR(t); err == nil {
		return cidr.String()
	}

	ip := net.ParseIP(t)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		}
		return ip.String()[:19] + "::/64"
	}

	parts := strings.Split(t, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}

	return "other"
}

func (s *TaskSplitter) MergeResults(parentID string) (merged bool, err error) {
	var n int64
	if err := s.db.Model(&model.ScanTask{}).Where("id = ?", parentID).Count(&n).Error; err != nil {
		return false, err
	}
	if n == 0 {
		return false, fmt.Errorf("父任务不存在: %s", parentID)
	}

	var subTasks []model.ScanTask
	if err := s.db.Where("parent_id = ?", parentID).Find(&subTasks).Error; err != nil {
		return false, fmt.Errorf("查询子任务失败: %w", err)
	}
	if len(subTasks) == 0 {
		return false, nil
	}

	allDone := true
	for _, sub := range subTasks {
		if !isScanTaskTerminalStatus(sub.Status) {
			allDone = false
			break
		}
	}

	if !allDone {
		return false, nil
	}

	var totalFindings int64
	var completedCount, failedCount, cancelledCount, partialCount int
	scannedSum := 0
	openPortsSum := 0
	aliveSum := 0
	var vc, vh, vm, vl, vi int

	for _, sub := range subTasks {
		var count int64
		s.db.Model(&model.ScanFinding{}).Where("task_id = ?", sub.ID).Count(&count)
		totalFindings += count

		switch sub.Status {
		case model.TaskStatusCompleted:
			completedCount++
		case model.TaskStatusPartial:
			partialCount++
		case model.TaskStatusFailed:
			failedCount++
		case model.TaskStatusCancelled:
			cancelledCount++
		}
		scannedSum += sub.ScannedTargets
		openPortsSum += sub.OpenPorts
		aliveSum += sub.AliveHosts
		vc += sub.VulnCritical
		vh += sub.VulnHigh
		vm += sub.VulnMedium
		vl += sub.VulnLow
		vi += sub.VulnInfo
	}

	parentStatus := model.TaskStatusCompleted
	if completedCount == len(subTasks) {
		parentStatus = model.TaskStatusCompleted
	} else if failedCount == len(subTasks) {
		parentStatus = model.TaskStatusFailed
	} else if cancelledCount == len(subTasks) {
		parentStatus = model.TaskStatusCancelled
	} else if completedCount > 0 || partialCount > 0 {
		parentStatus = model.TaskStatusPartial
	} else {
		parentStatus = model.TaskStatusFailed
	}

	now := time.Now()
	updates := map[string]interface{}{
		"status":          parentStatus,
		"updated_at":      now,
		"finished_at":     &now,
		"progress":        100,
		"scanned_targets": scannedSum,
		"open_ports":      openPortsSum,
		"alive_hosts":     aliveSum,
		"vuln_critical":   vc,
		"vuln_high":       vh,
		"vuln_medium":     vm,
		"vuln_low":        vl,
		"vuln_info":       vi,
		"current_stage":   "",
		"current_module":  "",
	}

	if err := s.db.Model(&model.ScanTask{}).Where("id = ?", parentID).Updates(updates).Error; err != nil {
		return false, fmt.Errorf("更新父任务状态失败: %w", err)
	}

	slog.Info("[TaskSplitter] 子任务结果合并完成",
		"parent", parentID,
		"subs", len(subTasks),
		"completed", completedCount,
		"partial", partialCount,
		"failed", failedCount,
		"cancelled", cancelledCount,
		"parent_status", parentStatus,
		"total_findings", totalFindings,
	)

	return true, nil
}

func isScanTaskTerminalStatus(s string) bool {
	switch s {
	case model.TaskStatusCompleted, model.TaskStatusFailed, model.TaskStatusCancelled, model.TaskStatusPartial:
		return true
	default:
		return false
	}
}
