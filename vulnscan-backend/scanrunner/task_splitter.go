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
		sub := model.ScanTask{
			ID:       subID,
			Name:     fmt.Sprintf("%s [分片 %d/%d: %s]", parentTask.Name, i+1, len(groups), group.key),
			Targets:  group.targets,
			Profile:  parentTask.Profile,
			Config:   parentTask.Config,
			Status:   "pending",
			ParentID: parentTask.ID,
		}
		subTasks = append(subTasks, sub)
	}

	if err := s.db.Model(&parentTask).Updates(map[string]interface{}{
		"status":    "splitting",
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

func (s *TaskSplitter) MergeResults(parentID string) error {
	var subTasks []model.ScanTask
	if err := s.db.Where("parent_id = ?", parentID).Find(&subTasks).Error; err != nil {
		return fmt.Errorf("查询子任务失败: %w", err)
	}

	allDone := true
	for _, sub := range subTasks {
		if sub.Status != "completed" && sub.Status != "failed" && sub.Status != "cancelled" {
			allDone = false
			break
		}
	}

	if !allDone {
		return nil
	}

	var totalFindings int64
	var completedCount, failedCount int
	for _, sub := range subTasks {
		var count int64
		s.db.Model(&model.ScanFinding{}).Where("task_id = ?", sub.ID).Count(&count)
		totalFindings += count

		switch sub.Status {
		case "completed":
			completedCount++
		case "failed":
			failedCount++
		}
	}

	parentStatus := "completed"
	if failedCount == len(subTasks) {
		parentStatus = "failed"
	} else if failedCount > 0 {
		parentStatus = "partial"
	}

	s.db.Model(&model.ScanTask{}).Where("id = ?", parentID).Updates(map[string]interface{}{
		"status":     parentStatus,
		"updated_at": time.Now(),
	})

	slog.Info("[TaskSplitter] 子任务结果合并完成",
		"parent", parentID,
		"subs", len(subTasks),
		"completed", completedCount,
		"failed", failedCount,
		"total_findings", totalFindings,
	)

	return nil
}
