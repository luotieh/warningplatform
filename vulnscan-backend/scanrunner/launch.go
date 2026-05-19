package scanrunner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// AssetEnrichTemplateID 内置「资产信息富化」扫描模板 ID（与模板表 id/code 一致）。
const AssetEnrichTemplateID = "asset-enrich"

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

	splitter := NewTaskSplitter(db)

	remoteWorkers := RemoteWorkerIDs(executorIDs)
	autoShard := len(remoteWorkers) > 1
	if autoShard {
		params["worker_target_sharding"] = true
	}

	// 多 Worker 目标分片：子任务 worker_id 非空时仅由对应 Worker Poll 领取，不进入本机内存队列。
	if workerTargetShardingEnabled(params) || autoShard {
		probe := model.ScanTask{Targets: p.Targets, Parameters: params}
		shards, err := ShardScanTaskByWorkers(db, context.Background(), probe, remoteWorkers)
		if err != nil {
			return nil, fmt.Errorf("worker target shard: %w", err)
		}
		multi := len(shards) > 1
		pinned := false
		for _, sh := range shards {
			if strings.TrimSpace(sh.WorkerID) != "" {
				pinned = true
				break
			}
		}
		if multi || pinned {
			now := time.Now()
			parent := model.ScanTask{
				ID:           qulid.GenerateID(),
				Name:         p.Name,
				TemplateID:   tmpl.ID,
				TemplateName: tmpl.Name,
				Targets:      p.Targets,
				Parameters:   params,
				Priority:     priority,
				Status:       model.TaskStatusSplitting,
				TotalTargets: len(p.Targets),
				ScheduleID:   p.ScheduleID,
				CreatedBy:    p.CreatedBy,
				OrganizeID:   p.OrganizeID,
				Type:         p.TaskType,
				ParentID:     p.ParentTaskID,
				CreatedAt:    now,
				UpdatedAt:    now,
			}
			if err := db.Create(&parent).Error; err != nil {
				return nil, fmt.Errorf("create parent task: %w", err)
			}

			for i, sh := range shards {
				subParams := stripWorkerShardSchedulingParams(params)
				subParams["_shard_index"] = i + 1
				subParams["_total_shards"] = len(shards)
				subNow := time.Now()
				wid := strings.TrimSpace(sh.WorkerID)
				sub := model.ScanTask{
					ID:           qulid.GenerateID(),
					Name:         fmt.Sprintf("%s [节点分片 %d/%d]", p.Name, i+1, len(shards)),
					TemplateID:   tmpl.ID,
					TemplateName: tmpl.Name,
					Type:         p.TaskType,
					Targets:      sh.Targets,
					Parameters:   subParams,
					Priority:     priority,
					ScheduleID:   p.ScheduleID,
					CreatedBy:    p.CreatedBy,
					OrganizeID:   p.OrganizeID,
					Status:       model.TaskStatusQueued,
					TotalTargets: len(sh.Targets),
					ParentID:     parent.ID,
					WorkerID:     wid,
					CreatedAt:    subNow,
					UpdatedAt:    subNow,
				}
				if err := db.Create(&sub).Error; err != nil {
					return nil, fmt.Errorf("create shard subtask: %w", err)
				}
				if wid == "" {
					sched.Enqueue(&sub)
				}
			}

			if err := db.Model(&parent).Updates(map[string]interface{}{
				"sub_count": len(shards),
			}).Error; err != nil {
				return nil, fmt.Errorf("update parent sub_count: %w", err)
			}

			slog.Info("[LaunchScan] 多节点目标分片已创建",
				"parent_task_id", parent.ID,
				"shards", len(shards),
				"template", tmpl.ID,
			)
			return &LaunchScanResult{Task: &parent, SplitMode: true, SubCount: len(shards)}, nil
		}
	}

	task := model.ScanTask{
		ID:           qulid.GenerateID(),
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

	if splitter.ShouldSplit(p.Targets) {
		task.Status = model.TaskStatusSplitting
		if err := db.Create(&task).Error; err != nil {
			return nil, fmt.Errorf("create parent task: %w", err)
		}

		subTasks, err := splitter.Split(task)
		if err != nil {
			return nil, fmt.Errorf("split task: %w", err)
		}

		for i := range subTasks {
			sched.Enqueue(&subTasks[i])
		}

		return &LaunchScanResult{Task: &task, SplitMode: true, SubCount: len(subTasks)}, nil
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
		ID:           qulid.GenerateID(),
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
