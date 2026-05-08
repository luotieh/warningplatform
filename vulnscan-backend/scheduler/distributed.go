package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// DistributedScheduler extends Scheduler with multi-node watchdog and rebalancing.
type DistributedScheduler struct {
	*Scheduler
	heartbeatTimeout time.Duration
}

func NewDistributed(db *gorm.DB, maxParallel int) *DistributedScheduler {
	return &DistributedScheduler{
		Scheduler:        New(db, maxParallel),
		heartbeatTimeout: 60 * time.Second,
	}
}

// StartWithWatchdog starts scheduler + stale worker watchdog + orphan recovery + rebalancing.
func (d *DistributedScheduler) StartWithWatchdog(ctx context.Context) {
	d.Scheduler.Start(ctx)

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-d.stopCh:
				return
			case <-ticker.C:
				d.checkStaleWorkers(ctx)
				d.recoverOrphanedTasks(ctx)
			}
		}
	}()

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		rebalanceTicker := time.NewTicker(2 * time.Minute)
		defer rebalanceTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-d.stopCh:
				return
			case <-rebalanceTicker.C:
				d.rebalance(ctx)
			}
		}
	}()

	slog.Info("[DistScheduler] 分布式调度器启动",
		"heartbeat_timeout", d.heartbeatTimeout,
	)
}

// --- Stale Worker Detection ---

func (d *DistributedScheduler) checkStaleWorkers(ctx context.Context) {
	threshold := time.Now().Add(-d.heartbeatTimeout)

	var staleWorkers []model.WorkerNode
	d.db.WithContext(ctx).
		Where("status = ? AND last_heartbeat < ?", model.WorkerStatusOnline, threshold).
		Find(&staleWorkers)

	if len(staleWorkers) == 0 {
		return
	}

	var ids []string
	for _, w := range staleWorkers {
		ids = append(ids, w.ID)
		slog.Warn("[DistScheduler] Worker 失联",
			"worker_id", w.ID,
			"hostname", w.Hostname,
			"offline_duration", time.Since(w.LastHeartbeat).Round(time.Second),
		)
	}

	d.db.WithContext(ctx).
		Model(&model.WorkerNode{}).
		Where("id IN ?", ids).
		Updates(map[string]interface{}{
			"status":       model.WorkerStatusOffline,
			"active_tasks": 0,
		})

	d.recoverTasksFromWorkers(ctx, ids)
}

func (d *DistributedScheduler) recoverTasksFromWorkers(ctx context.Context, workerIDs []string) {
	var tasks []model.ScanTask
	d.db.WithContext(ctx).
		Where("worker_id IN ? AND status = ?", workerIDs, model.TaskStatusRunning).
		Find(&tasks)

	if len(tasks) == 0 {
		return
	}

	for _, task := range tasks {
		d.db.WithContext(ctx).
			Model(&model.ScanTask{}).
			Where("id = ?", task.ID).
			Updates(map[string]interface{}{
				"status":    model.TaskStatusQueued,
				"worker_id": "",
				"error_msg": fmt.Sprintf("Worker %s 失联，任务自动回收重新排队", task.WorkerID),
			})

		d.Enqueue(&task)

		slog.Info("[DistScheduler] 任务已回收并重新入队",
			"task_id", task.ID,
			"from_worker", task.WorkerID,
		)
	}
}

func (d *DistributedScheduler) recoverOrphanedTasks(ctx context.Context) {
	stuckThreshold := time.Now().Add(-10 * time.Minute)

	var tasks []model.ScanTask
	d.db.WithContext(ctx).
		Where("status = ? AND started_at < ? AND (worker_id = '' OR worker_id IS NULL)",
			model.TaskStatusRunning, stuckThreshold).
		Find(&tasks)

	for _, task := range tasks {
		d.db.WithContext(ctx).
			Model(&model.ScanTask{}).
			Where("id = ?", task.ID).
			Updates(map[string]interface{}{
				"status":    model.TaskStatusQueued,
				"error_msg": "任务卡死（无Worker），自动重新排队",
			})

		d.Enqueue(&task)

		slog.Warn("[DistScheduler] 孤儿任务回收", "task_id", task.ID)
	}
}

// --- Task Sharding ---

type TaskShard struct {
	ShardIndex  int
	TotalShards int
	Targets     []string
	WorkerID    string
}

// ShardTask splits a task's targets across available workers, sorted by HealthScore.
func (d *DistributedScheduler) ShardTask(ctx context.Context, task model.ScanTask) ([]TaskShard, error) {
	var workers []model.WorkerNode
	err := d.db.WithContext(ctx).
		Where("status = ? AND active_tasks < capacity", model.WorkerStatusOnline).
		Find(&workers).Error
	if err != nil {
		return nil, err
	}

	workerCount := len(workers)
	if workerCount == 0 {
		return []TaskShard{{ShardIndex: 0, TotalShards: 1, Targets: task.Targets}}, nil
	}

	targetCount := len(task.Targets)
	if targetCount <= 10 || workerCount <= 1 {
		return []TaskShard{{ShardIndex: 0, TotalShards: 1, Targets: task.Targets}}, nil
	}

	sort.Slice(workers, func(i, j int) bool {
		return workers[i].HealthScore() > workers[j].HealthScore()
	})

	shardCount := workerCount
	if shardCount > targetCount {
		shardCount = targetCount
	}

	totalCapacity := 0.0
	for i := 0; i < shardCount; i++ {
		totalCapacity += workers[i].HealthScore()
	}

	var shards []TaskShard
	assigned := 0

	for i := 0; i < shardCount; i++ {
		var count int
		if i == shardCount-1 {
			count = targetCount - assigned
		} else if totalCapacity > 0 {
			ratio := workers[i].HealthScore() / totalCapacity
			count = int(math.Round(float64(targetCount) * ratio))
		} else {
			count = int(math.Ceil(float64(targetCount-assigned) / float64(shardCount-i)))
		}

		if count <= 0 {
			count = 1
		}
		if assigned+count > targetCount {
			count = targetCount - assigned
		}
		if count <= 0 {
			break
		}

		shards = append(shards, TaskShard{
			ShardIndex:  i,
			TotalShards: shardCount,
			Targets:     task.Targets[assigned : assigned+count],
			WorkerID:    workers[i].ID,
		})
		assigned += count
	}

	return shards, nil
}

// --- Rebalancing ---

// rebalance detects load imbalance across workers and migrates queued tasks.
func (d *DistributedScheduler) rebalance(ctx context.Context) {
	var workers []model.WorkerNode
	d.db.WithContext(ctx).
		Where("status = ?", model.WorkerStatusOnline).
		Find(&workers)

	if len(workers) < 2 {
		return
	}

	var totalLoad float64
	for i := range workers {
		totalLoad += workers[i].LoadRatio()
	}
	avgLoad := totalLoad / float64(len(workers))

	var overloaded, underloaded []model.WorkerNode
	for i := range workers {
		ratio := workers[i].LoadRatio()
		if ratio > avgLoad*1.3 && workers[i].ActiveTasks > 1 {
			overloaded = append(overloaded, workers[i])
		} else if ratio < avgLoad*0.7 {
			underloaded = append(underloaded, workers[i])
		}
	}

	if len(overloaded) == 0 || len(underloaded) == 0 {
		return
	}

	migrated := 0
	for _, heavy := range overloaded {
		var queuedTasks []model.ScanTask
		d.db.WithContext(ctx).
			Where("worker_id = ? AND status = ?", heavy.ID, model.TaskStatusQueued).
			Limit(2).
			Find(&queuedTasks)

		for _, task := range queuedTasks {
			if len(underloaded) == 0 {
				break
			}

			sort.Slice(underloaded, func(i, j int) bool {
				return underloaded[i].HealthScore() > underloaded[j].HealthScore()
			})
			target := underloaded[0]

			d.db.WithContext(ctx).
				Model(&model.ScanTask{}).
				Where("id = ? AND status = ?", task.ID, model.TaskStatusQueued).
				Update("worker_id", target.ID)

			migrated++

			slog.Info("[DistScheduler] 任务再平衡",
				"task_id", task.ID,
				"from", heavy.ID,
				"to", target.ID,
			)
		}
	}

	if migrated > 0 {
		slog.Info("[DistScheduler] 再平衡完成", "migrated_tasks", migrated)
	}
}
