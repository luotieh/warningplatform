package monitoragent

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"vulnscan-backend/agent"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type EmbeddedAgent struct {
	db        *db.DB
	scheduler *agent.Scheduler
	executor  *DBExecutor
	agentUUID string
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func NewEmbeddedAgent(database *db.DB, masterBaseURL string) *EmbeddedAgent {
	return &EmbeddedAgent{
		db:        database,
		agentUUID: "embedded-default",
	}
}

func (e *EmbeddedAgent) Start() {
	session, err := e.db.GetDBSession()
	if err != nil {
		slog.Error("embedded agent: DB session error", "error", err)
		return
	}

	// Register in both legacy and new node tables
	e.registerNode(session)

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel

	e.executor = NewDBExecutor(session)
	if err := e.executor.Init(ctx); err != nil {
		slog.Error("embedded agent: executor init failed", "error", err)
		cancel()
		return
	}

	e.scheduler = agent.NewSchedulerOnly(
		[]agent.Executor{e.executor},
		5,
		5*time.Minute,
	)
	e.scheduler.SetResultCallback(func(result *agent.TaskResult) {
		e.saveResultToDB(session, result)
	})

	e.wg.Add(1)
	go e.runDirectLoop(ctx, session)

	slog.Info("embedded agent started", "uuid", e.agentUUID, "concurrency", 5)
}

func (e *EmbeddedAgent) registerNode(session *gorm.DB) {
	var existing model.MonitorAgent
	err := session.Where("uuid = ?", e.agentUUID).First(&existing).Error
	if err != nil {
		ma := model.MonitorAgent{
			UUID:          e.agentUUID,
			Status:        "online",
			Version:       agent.Version,
			MacAddress:    "local",
			IPAddress:     "127.0.0.1",
			MaxConcurrent: 5,
			MaxQueue:      100,
		}
		ma.ID = e.agentUUID
		session.Create(&ma)
	} else {
		session.Model(&model.MonitorAgent{}).
			Where("uuid = ?", e.agentUUID).
			Updates(map[string]any{
				"status":         "online",
				"version":        agent.Version,
				"last_heartbeat": time.Now(),
				"max_concurrent": 5,
				"max_queue":      100,
			})
	}

	// Also register in unified node table
	var node model.Node
	if session.Where("uuid = ?", e.agentUUID).First(&node).Error != nil {
		node = model.Node{
			ID:            e.agentUUID,
			UUID:          e.agentUUID,
			Status:        model.NodeStatusOnline,
			Version:       agent.Version,
			IPAddress:     "127.0.0.1",
			MacAddress:    "local",
			Hostname:      "embedded",
			MaxConcurrent: 5,
		}
		session.Create(&node)
	} else {
		session.Model(&model.Node{}).
			Where("uuid = ?", e.agentUUID).
			Updates(map[string]any{
				"status":         model.NodeStatusOnline,
				"version":        agent.Version,
				"last_heartbeat": time.Now(),
			})
	}
}

func (e *EmbeddedAgent) runDirectLoop(ctx context.Context, session *gorm.DB) {
	defer e.wg.Done()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	heartbeatTicker := time.NewTicker(15 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.scheduler.WaitWithTimeout(30 * time.Second)
			e.executor.Close()
			return
		case <-heartbeatTicker.C:
			e.executor.RefreshRules(ctx)
			session.Model(&model.MonitorAgent{}).
				Where("uuid = ?", e.agentUUID).
				Updates(map[string]any{
					"status":         "online",
					"last_heartbeat": time.Now(),
					"running_tasks":  e.scheduler.RunningCount(),
					"queued_tasks":   e.scheduler.QueuedCount(),
				})
			session.Model(&model.Node{}).
				Where("uuid = ?", e.agentUUID).
				Updates(map[string]any{
					"status":         model.NodeStatusOnline,
					"last_heartbeat": time.Now(),
					"running_tasks":  e.scheduler.RunningCount(),
					"queued_tasks":   e.scheduler.QueuedCount(),
				})
		case <-ticker.C:
			available := 5 - e.scheduler.RunningCount() - e.scheduler.QueuedCount()
			if available <= 0 {
				continue
			}

			batch := available
			if batch > 5 {
				batch = 5
			}

			var executions []model.MonitorExecution
			result := session.
				Where("status = ? AND (agent_id IS NULL OR agent_id = '')", "pending").
				Order("created_at ASC").
				Limit(batch).
				Find(&executions)
			if result.Error != nil || len(executions) == 0 {
				continue
			}

			ids := make([]string, len(executions))
			for i, ex := range executions {
				ids[i] = ex.ID
			}

			res := session.Model(&model.MonitorExecution{}).
				Where("id IN ? AND (agent_id IS NULL OR agent_id = '')", ids).
				Updates(map[string]any{
					"agent_id": e.agentUUID,
					"status":   "running",
				})
			if res.RowsAffected == 0 {
				continue
			}

			session.Where("id IN ? AND agent_id = ?", ids, e.agentUUID).
				Find(&executions)

			for _, exec := range executions {
				var task model.MonitorTask
				if err := session.First(&task, "id = ?", exec.TaskID).Error; err != nil {
					continue
				}

				payload, _ := json.Marshal(TaskMessage{
					ExecutionID: exec.ID,
					TaskID:      task.ID,
					Dimension:   exec.Dimension,
					URL:         task.TargetHomepage,
				})

				e.scheduler.Submit(&agent.TaskEnvelope{
					ID:      exec.ID,
					Type:    "monitor",
					Payload: payload,
				})
			}
		}
	}
}

func (e *EmbeddedAgent) saveResultToDB(session *gorm.DB, result *agent.TaskResult) {
	session.Model(&model.MonitorExecution{}).
		Where("id = ?", result.ID).
		Updates(map[string]any{
			"status":      result.Status,
			"error":       result.Error,
			"result_json": result.Result,
		})

	session.Model(&model.MonitorAgent{}).
		Where("uuid = ?", e.agentUUID).
		UpdateColumn("tasks_completed", gorm.Expr("tasks_completed + 1"))

	session.Model(&model.Node{}).
		Where("uuid = ?", e.agentUUID).
		UpdateColumn("tasks_completed", gorm.Expr("tasks_completed + 1"))
}

func (e *EmbeddedAgent) Stop() {
	if e.cancel != nil {
		e.cancel()
	}

	session, err := e.db.GetDBSession()
	if err == nil {
		session.Model(&model.MonitorAgent{}).
			Where("uuid = ?", e.agentUUID).
			Updates(map[string]any{"status": "offline"})
		session.Model(&model.Node{}).
			Where("uuid = ?", e.agentUUID).
			Updates(map[string]any{"status": model.NodeStatusOffline})
	}

	e.wg.Wait()
	slog.Info("embedded agent stopped")
}
