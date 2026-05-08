package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	clusterContract "vulnscan-backend/cluster/cluster-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceCluster struct {
	db *db.DB

	pendingCmds map[string][]clusterContract.WorkerCommand
	cmdMu       sync.Mutex
}

func NewServiceCluster(database *db.DB) *serviceCluster {
	return &serviceCluster{
		db:          database,
		pendingCmds: make(map[string][]clusterContract.WorkerCommand),
	}
}

// NewServiceClusterForWS creates a ServiceCluster for use by the WS Hub.
func NewServiceClusterForWS(database *db.DB) clusterContract.ServiceCluster {
	return NewServiceCluster(database)
}

func (s *serviceCluster) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

// --- Worker Lifecycle ---

func (s *serviceCluster) RegisterWorker(ctx context.Context, node *model.WorkerNode) error {
	node.Status = model.WorkerStatusOnline
	node.RegisteredAt = time.Now()
	node.LastHeartbeat = time.Now()

	result := s.session().WithContext(ctx).
		Where("id = ?", node.ID).
		Assign(model.WorkerNode{
			Name:          node.Name,
			Hostname:      node.Hostname,
			IP:            node.IP,
			Port:          node.Port,
			Version:       node.Version,
			Status:        node.Status,
			Capacity:      node.Capacity,
			LastHeartbeat: node.LastHeartbeat,
			RegisteredAt:  node.RegisteredAt,
		}).
		FirstOrCreate(node)

	if result.Error != nil {
		return fmt.Errorf("register worker failed: %w", result.Error)
	}

	slog.Info("[Cluster] Worker 注册成功", "worker_id", node.ID, "hostname", node.Hostname, "ip", node.IP)
	return nil
}

// Heartbeat updates worker status and returns pending commands (bidirectional channel).
func (s *serviceCluster) Heartbeat(ctx context.Context, payload *clusterContract.HeartbeatPayload) (*clusterContract.HeartbeatResponse, error) {
	updates := map[string]interface{}{
		"status":              model.WorkerStatusOnline,
		"active_tasks":        payload.ActiveTasks,
		"capacity":            payload.Capacity,
		"cpu_usage":           payload.CPUUsage,
		"mem_usage":           payload.MemUsage,
		"version":             payload.Version,
		"bandwidth_mbps":      payload.BandwidthMbps,
		"avg_latency_ms":      payload.AvgLatencyMs,
		"proxy_healthy_count": payload.ProxyHealthyCount,
		"proxy_total_count":   payload.ProxyTotalCount,
		"last_heartbeat":      time.Now(),
	}

	if len(payload.BannedTargets) > 0 {
		updates["banned_targets"] = model.StringArray(payload.BannedTargets)
	}

	result := s.session().WithContext(ctx).
		Model(&model.WorkerNode{}).
		Where("id = ?", payload.WorkerID).
		Updates(updates)

	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("worker %s not found", payload.WorkerID)
	}
	if result.Error != nil {
		return nil, result.Error
	}

	s.cmdMu.Lock()
	cmds := s.pendingCmds[payload.WorkerID]
	delete(s.pendingCmds, payload.WorkerID)
	s.cmdMu.Unlock()

	return &clusterContract.HeartbeatResponse{
		OK:       true,
		Commands: cmds,
	}, nil
}

// SendCommand enqueues a command to be delivered on the worker's next heartbeat.
func (s *serviceCluster) SendCommand(workerID string, cmd clusterContract.WorkerCommand) {
	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()
	s.pendingCmds[workerID] = append(s.pendingCmds[workerID], cmd)
}

func (s *serviceCluster) UnregisterWorker(ctx context.Context, workerID string) error {
	return s.session().WithContext(ctx).
		Model(&model.WorkerNode{}).
		Where("id = ?", workerID).
		Updates(map[string]interface{}{
			"status":       model.WorkerStatusOffline,
			"active_tasks": 0,
		}).Error
}

func (s *serviceCluster) ListWorkers(query clusterContract.WorkerQuery) ([]model.WorkerNode, int64, error) {
	var items []model.WorkerNode
	var count int64

	tx := s.session().Model(&model.WorkerNode{})

	if query.Status != "" {
		tx = tx.Where("status = ?", query.Status)
	}

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 || query.PageSize > 100 {
		query.PageSize = 20
	}

	offset := (query.Page - 1) * query.PageSize
	if err := tx.Offset(offset).Limit(query.PageSize).Order("last_heartbeat DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}

	return items, count, nil
}

func (s *serviceCluster) GetWorker(id string) (*model.WorkerNode, error) {
	var node model.WorkerNode
	if err := s.session().First(&node, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &node, nil
}

// --- Task Operations (atomic, no race condition) ---

// PollTask atomically claims up to `slots` queued tasks for the given worker.
// Uses UPDATE ... WHERE status='queued' to prevent race conditions.
func (s *serviceCluster) PollTask(ctx context.Context, workerID string, slots int) ([]*model.ScanTask, error) {
	if slots <= 0 {
		slots = 1
	}
	if slots > 5 {
		slots = 5
	}

	var worker model.WorkerNode
	if err := s.session().WithContext(ctx).Where("id = ?", workerID).First(&worker).Error; err != nil {
		return nil, fmt.Errorf("worker not found: %s", workerID)
	}

	available := worker.EffectiveCapacity() - worker.ActiveTasks
	if available <= 0 {
		return nil, nil
	}
	if slots > available {
		slots = available
	}

	var candidates []model.ScanTask
	if err := s.session().WithContext(ctx).
		Where("status = ? AND (worker_id = '' OR worker_id IS NULL)", model.TaskStatusQueued).
		Order("priority DESC, created_at ASC").
		Limit(slots * 2).
		Find(&candidates).Error; err != nil {
		return nil, err
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	var claimed []*model.ScanTask
	now := time.Now()

	for i := range candidates {
		if len(claimed) >= slots {
			break
		}

		task := &candidates[i]

		result := s.session().WithContext(ctx).
			Model(&model.ScanTask{}).
			Where("id = ? AND status = ?", task.ID, model.TaskStatusQueued).
			Updates(map[string]interface{}{
				"status":     model.TaskStatusRunning,
				"worker_id":  workerID,
				"started_at": &now,
			})

		if result.RowsAffected == 1 {
			task.Status = model.TaskStatusRunning
			task.WorkerID = workerID
			task.StartedAt = &now
			claimed = append(claimed, task)
		}
	}

	if len(claimed) > 0 {
		s.session().WithContext(ctx).
			Model(&model.WorkerNode{}).
			Where("id = ?", workerID).
			Update("active_tasks", gorm.Expr("active_tasks + ?", len(claimed)))

		slog.Info("[Cluster] Worker 领取任务",
			"worker_id", workerID,
			"claimed", len(claimed),
		)
	}

	return claimed, nil
}

// ReportTaskResult processes task completion/failure reports from workers.
func (s *serviceCluster) ReportTaskResult(ctx context.Context, result *clusterContract.TaskResult) error {
	updates := map[string]interface{}{
		"status":        result.Status,
		"progress":      result.Progress,
		"current_stage": result.CurrentStage,
	}
	if result.Error != "" {
		updates["error_msg"] = result.Error
	}
	if result.FinishedAt != nil {
		updates["finished_at"] = result.FinishedAt
	}

	sess := s.session()
	if ctx != nil {
		sess = sess.WithContext(ctx)
	}

	if err := sess.Model(&model.ScanTask{}).
		Where("id = ?", result.TaskID).
		Updates(updates).Error; err != nil {
		return err
	}

	if len(result.Vulnerabilities) > 0 {
		s.saveVulnerabilities(sess, result.TaskID, result.Vulnerabilities)
	}

	if result.Status == model.TaskStatusCompleted || result.Status == model.TaskStatusFailed {
		sess.Model(&model.WorkerNode{}).
			Where("id = ? AND active_tasks > 0", result.WorkerID).
			Update("active_tasks", gorm.Expr("active_tasks - 1"))

		counterField := "success_task_count"
		if result.Status == model.TaskStatusFailed {
			counterField = "failed_task_count"
		}
		sess.Model(&model.WorkerNode{}).
			Where("id = ?", result.WorkerID).
			Update(counterField, gorm.Expr(counterField+" + 1"))
	}

	return nil
}

func (s *serviceCluster) saveVulnerabilities(sess *gorm.DB, taskID string, vulns []model.Vulnerability) {
	if len(vulns) == 0 {
		return
	}

	var assets []model.Asset
	sess.Select("id, address, ipv4, domain, url, port").Find(&assets)
	assetIndex := buildAssetIndex(assets)

	for i := range vulns {
		vulns[i].TaskID = taskID
		if vulns[i].ID == "" {
			vulns[i].ID = generateVulnID()
		}
		vulns[i].AssetID = matchAsset(assetIndex, vulns[i].Target, vulns[i].Port)
	}

	sess.CreateInBatches(vulns, 100)
}

type assetIndexEntry struct {
	ID   string
	Port int
}

func buildAssetIndex(assets []model.Asset) map[string][]assetIndexEntry {
	idx := make(map[string][]assetIndexEntry, len(assets)*3)
	for _, a := range assets {
		entry := assetIndexEntry{ID: a.ID, Port: a.Port}
		if a.Address != "" {
			idx[a.Address] = append(idx[a.Address], entry)
		}
		if a.IPv4 != "" && a.IPv4 != a.Address {
			idx[a.IPv4] = append(idx[a.IPv4], entry)
		}
		if a.Domain != "" {
			idx[a.Domain] = append(idx[a.Domain], entry)
		}
		if a.URL != "" {
			idx[a.URL] = append(idx[a.URL], entry)
		}
	}
	return idx
}

func matchAsset(idx map[string][]assetIndexEntry, target string, port int) string {
	if entries, ok := idx[target]; ok {
		for _, e := range entries {
			if port == 0 || e.Port == 0 || e.Port == port {
				return e.ID
			}
		}
		return entries[0].ID
	}
	return ""
}

func generateVulnID() string {
	return fmt.Sprintf("vuln_%d", time.Now().UnixNano())
}

// ReportBan handles a worker reporting that it was banned by a target site.
func (s *serviceCluster) ReportBan(ctx context.Context, report *clusterContract.BanReport) error {
	slog.Warn("[Cluster] Worker 报告IP封禁",
		"worker_id", report.WorkerID,
		"task_id", report.TaskID,
		"target", report.TargetHost,
		"reason", report.Reason,
	)

	s.session().WithContext(ctx).
		Model(&model.WorkerNode{}).
		Where("id = ?", report.WorkerID).
		Update("status", model.WorkerStatusDrain)

	var task model.ScanTask
	if err := s.session().WithContext(ctx).Where("id = ?", report.TaskID).First(&task).Error; err != nil {
		return err
	}

	if task.Status == model.TaskStatusRunning {
		s.session().WithContext(ctx).
			Model(&model.ScanTask{}).
			Where("id = ?", report.TaskID).
			Updates(map[string]interface{}{
				"status":    model.TaskStatusQueued,
				"worker_id": "",
				"error_msg": fmt.Sprintf("Worker %s 被目标 %s 封禁(%s)，任务重新分配", report.WorkerID, report.TargetHost, report.Reason),
			})

		s.session().WithContext(ctx).
			Model(&model.WorkerNode{}).
			Where("id = ? AND active_tasks > 0", report.WorkerID).
			Update("active_tasks", gorm.Expr("active_tasks - 1"))
	}

	return nil
}

// --- Stale Worker Detection ---

func (s *serviceCluster) CheckStaleWorkers(ctx context.Context, timeout time.Duration) ([]model.WorkerNode, error) {
	threshold := time.Now().Add(-timeout)
	var staleWorkers []model.WorkerNode

	err := s.session().WithContext(ctx).
		Where("status = ? AND last_heartbeat < ?", model.WorkerStatusOnline, threshold).
		Find(&staleWorkers).Error
	if err != nil {
		return nil, err
	}

	if len(staleWorkers) == 0 {
		return nil, nil
	}

	var ids []string
	for _, w := range staleWorkers {
		ids = append(ids, w.ID)
	}

	s.session().WithContext(ctx).
		Model(&model.WorkerNode{}).
		Where("id IN ?", ids).
		Updates(map[string]interface{}{
			"status":       model.WorkerStatusOffline,
			"active_tasks": 0,
		})

	s.recoverTasksFromWorkers(ctx, ids)

	slog.Warn("[Cluster] 检测到失联Worker", "count", len(staleWorkers), "ids", ids)
	return staleWorkers, nil
}

func (s *serviceCluster) recoverTasksFromWorkers(ctx context.Context, workerIDs []string) {
	var tasks []model.ScanTask
	s.session().WithContext(ctx).
		Where("worker_id IN ? AND status = ?", workerIDs, model.TaskStatusRunning).
		Find(&tasks)

	for _, task := range tasks {
		s.session().WithContext(ctx).
			Model(&model.ScanTask{}).
			Where("id = ?", task.ID).
			Updates(map[string]interface{}{
				"status":    model.TaskStatusQueued,
				"worker_id": "",
				"error_msg": fmt.Sprintf("Worker %s 失联，任务自动回收", task.WorkerID),
			})
		slog.Info("[Cluster] 任务已回收", "task_id", task.ID, "from_worker", task.WorkerID)
	}
}
