package scanrunner

import (
	"fmt"
	"strings"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// RerunScan 基于已有任务配置重新入队执行（生成新任务 ID）。
func RerunScan(db *gorm.DB, sched *Scheduler, taskID string) (*LaunchScanResult, error) {
	if db == nil || sched == nil {
		return nil, fmt.Errorf("db or scheduler is nil")
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("task id is empty")
	}

	var orig model.ScanTask
	if err := db.First(&orig, "id = ?", taskID).Error; err != nil {
		return nil, err
	}
	if pid := strings.TrimSpace(orig.ParentID); pid != "" {
		return RerunScan(db, sched, pid)
	}

	switch orig.Status {
	case model.TaskStatusRunning, model.TaskStatusQueued, model.TaskStatusPending,
		model.TaskStatusPaused, model.TaskStatusSplitting:
		return nil, fmt.Errorf("任务仍在执行中，无法重新运行")
	}

	name := strings.TrimSpace(orig.Name)
	if name == "" {
		name = "扫描任务"
	}
	if !strings.Contains(name, "重跑") {
		name = name + " (重跑)"
	}

	params := model.JSONMap{}
	for k, v := range orig.Parameters {
		params[k] = v
	}

	templateID := strings.TrimSpace(orig.TemplateID)
	if templateID == "" {
		templateID = AssetEnrichTemplateID
	}

	return LaunchScan(db, sched, LaunchScanParams{
		Name:         name,
		Targets:      orig.Targets,
		TemplateID:   templateID,
		Parameters:   params,
		Priority:     orig.Priority,
		ScheduleID:   orig.ScheduleID,
		CreatedBy:    orig.CreatedBy,
		OrganizeID:   orig.OrganizeID,
		TaskType:     orig.Type,
		ParentTaskID: "",
	})
}
