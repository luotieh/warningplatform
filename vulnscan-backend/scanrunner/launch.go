package scanrunner

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// AssetEnrichTemplateID 内置「资产信息富化」扫描模板 ID（与模板表 id/code 一致）。
const AssetEnrichTemplateID = "asset-enrich"

// AssetDiscoveryTemplateID 内置「资产探测」扫描模板 ID（仅信息收集）。
const AssetDiscoveryTemplateID = "asset-discovery"

// ErrTemplateNotFound 模板不存在或未启用。
var ErrTemplateNotFound = errors.New("scan template not found or disabled")

// LaunchScanParams 与 HTTP Launch 等价，供资产富化等内部调用。
type LaunchScanParams struct {
	Name            string
	Targets         []string
	TemplateID      string
	Parameters      map[string]interface{}
	AssetIDs        []string // 与 Targets 一一对应；单元素时写入 parameters.asset_id
	ExecutorNodeIDs []string
	Priority        int
	ScheduleID      string
	CreatedBy       string
	OrganizeID      string
	TaskType        string
	ParentTaskID    string
}

// LaunchScanResult 单次启动扫描的结果。
type LaunchScanResult struct {
	Task      *model.ScanTask
	SplitMode bool
	SubCount  int
}

// LaunchScan 创建扫描任务并入队（逻辑与 API Launch 一致）。
func LaunchScan(db *gorm.DB, sched *Scheduler, p LaunchScanParams) (*LaunchScanResult, error) {
	if db == nil {
		return nil, fmt.Errorf("db is nil")
	}
	if sched == nil {
		return nil, fmt.Errorf("scheduler is nil")
	}
	if len(p.Targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}

	var tmpl model.ScanTemplate
	if err := db.Where("(id = ? OR code = ?) AND enabled = ?", p.TemplateID, p.TemplateID, true).First(&tmpl).Error; err != nil {
		return nil, ErrTemplateNotFound
	}

	priority := p.Priority
	if priority <= 0 {
		priority = 5
	}

	params := model.JSONMap{}
	for k, v := range p.Parameters {
		params[k] = v
	}
	if len(p.AssetIDs) > 0 {
		paramMap := make(map[string]interface{}, len(params)+4)
		for k, v := range params {
			paramMap[k] = v
		}
		for k, v := range MergeAssetIDsIntoParameters(paramMap, p.Targets, p.AssetIDs) {
			params[k] = v
		}
	}
	NormalizeTaskAssetParameters(params, p.Targets)
	executorIDs := NormalizeExecutorNodeIDs(p.ExecutorNodeIDs)
	ApplyExecutorNodeParams(params, executorIDs)

	if pinned := SinglePinnedWorkerID(executorIDs); pinned != "" {
		return launchPinnedWorkerScan(db, sched, p, tmpl, params, priority, pinned)
	}

	task := model.ScanTask{
		ID:           ulid.GenerateID(),
		Name:         p.Name,
		TemplateID:   tmpl.ID,
		TemplateName: tmpl.Name,
		Targets:      p.Targets,
		Parameters:   params,
		Priority:     priority,
		Status:       model.TaskStatusQueued,
		TotalTargets: len(p.Targets),
		ScheduleID:   p.ScheduleID,
		CreatedBy:    p.CreatedBy,
		OrganizeID:   p.OrganizeID,
		Type:         p.TaskType,
		ParentID:     p.ParentTaskID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := db.Create(&task).Error; err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}

	sched.Enqueue(&task)
	slog.Info("[LaunchScan] 任务已入队", "task_id", task.ID, "template", tmpl.ID, "targets", len(p.Targets), "executor", executorIDs)
	return &LaunchScanResult{Task: &task}, nil
}

func launchPinnedWorkerScan(db *gorm.DB, sched *Scheduler, p LaunchScanParams, tmpl model.ScanTemplate, params model.JSONMap, priority int, workerID string) (*LaunchScanResult, error) {
	now := time.Now()
	task := model.ScanTask{
		ID:           ulid.GenerateID(),
		Name:         p.Name,
		TemplateID:   tmpl.ID,
		TemplateName: tmpl.Name,
		Targets:      p.Targets,
		Parameters:   params,
		Priority:     priority,
		Status:       model.TaskStatusQueued,
		TotalTargets: len(p.Targets),
		ScheduleID:   p.ScheduleID,
		CreatedBy:    p.CreatedBy,
		OrganizeID:   p.OrganizeID,
		Type:         p.TaskType,
		ParentID:     p.ParentTaskID,
		WorkerID:     workerID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := db.Create(&task).Error; err != nil {
		return nil, fmt.Errorf("create pinned worker task: %w", err)
	}
	slog.Info("[LaunchScan] 任务已绑定远程节点", "task_id", task.ID, "worker_id", workerID)
	return &LaunchScanResult{Task: &task}, nil
}
