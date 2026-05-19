package monitoragent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/agent"
	"vulnscan-backend/model"
	"vulnscan-backend/pkg/nodeauth"
	"vulnscan-backend/pkg/nodecapacity"
	"vulnscan-backend/sitemonitor"

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

	capSnap := nodecapacity.Compute(nodecapacity.DefaultConfig())
	e.registerNode(session, capSnap.Capacity)

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
		capSnap.Capacity,
		5*time.Minute,
	)
	e.scheduler.SetResultCallback(func(result *agent.TaskResult) {
		e.saveResultToDB(session, result)
	})

	e.wg.Add(1)
	go e.runDirectLoop(ctx, session)

	slog.Info("embedded agent started", "uuid", e.agentUUID, "concurrency", capSnap.Capacity)
}

func (e *EmbeddedAgent) registerNode(session *gorm.DB, maxConcurrent int) {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	var existing model.MonitorAgent
	err := session.Where("uuid = ?", e.agentUUID).First(&existing).Error
	if err != nil {
		ma := model.MonitorAgent{
			UUID:          e.agentUUID,
			Status:        "online",
			Version:       agent.Version,
			MacAddress:    "local",
			IPAddress:     "127.0.0.1",
			MaxConcurrent: maxConcurrent,
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
				"max_concurrent": maxConcurrent,
				"max_queue":      100,
			})
	}

	// vs_nodes 登记仅供 node-api 鉴权；节点总览列表已排除 uuid=embedded-default，能力合并展示在「本地执行引擎」。
	var node model.Node
	errNode := session.Where("uuid = ?", e.agentUUID).First(&node).Error
	nodeExists := errNode == nil

	if nodeExists && node.AgentSecretHash != "" {
		session.Model(&model.Node{}).
			Where("uuid = ?", e.agentUUID).
			Updates(map[string]any{
				"status":         model.NodeStatusOnline,
				"version":        agent.Version,
				"last_heartbeat": time.Now(),
			})
	} else {
		plain, perr := resolveEmbeddedAgentPlainSecret(e.agentUUID)
		if perr != nil {
			slog.Error("embedded agent: node agent secret", "error", perr)
			return
		}
		hashStr, herr := nodeauth.HashSecret(plain)
		if herr != nil {
			slog.Error("embedded agent: hash node agent secret", "error", herr)
			return
		}
		if !nodeExists {
			session.Create(&model.Node{
				ID:              e.agentUUID,
				UUID:            e.agentUUID,
				AgentSecretHash: hashStr,
				Status:          model.NodeStatusOnline,
				Version:         agent.Version,
				IPAddress:       "127.0.0.1",
				MacAddress:      "local",
				Hostname:        "embedded",
				MaxConcurrent:   maxConcurrent,
			})
		} else {
			session.Model(&model.Node{}).
				Where("uuid = ?", e.agentUUID).
				Updates(map[string]any{
					"status":            model.NodeStatusOnline,
					"version":           agent.Version,
					"last_heartbeat":    time.Now(),
					"agent_secret_hash": hashStr,
				})
		}
	}
}

func embeddedAgentSecretFilePath() string {
	if p := strings.TrimSpace(os.Getenv("VULNSCAN_EMBEDDED_NODE_AGENT_SECRET_FILE")); p != "" {
		return filepath.Clean(p)
	}
	return filepath.Join(".", "embedded-default.agent.secret")
}

// resolveEmbeddedAgentPlainSecret reads VULNSCAN_EMBEDDED_NODE_AGENT_SECRET, optional file, or generates one and writes embedded-default.agent.secret (0600).
func resolveEmbeddedAgentPlainSecret(nodeUUID string) (string, error) {
	if v := strings.TrimSpace(os.Getenv("VULNSCAN_EMBEDDED_NODE_AGENT_SECRET")); v != "" {
		return v, nil
	}
	path := embeddedAgentSecretFilePath()
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	gen, err := nodeauth.GeneratePlainSecret()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(gen+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	slog.Warn("embedded agent: generated node-api secret file; use X-Agent-Token + X-Agent-Secret from this file for outbound calls",
		"path", path, "node_uuid", nodeUUID)
	return gen, nil
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
			maxConc := e.scheduler.MaxConcurrent()
			if maxConc < len(model.MonitorAllDimensions) {
				maxConc = len(model.MonitorAllDimensions)
			}
			available := maxConc - e.scheduler.RunningCount() - e.scheduler.QueuedCount()
			if available <= 0 {
				continue
			}

			batch := available
			if batch > maxConc {
				batch = maxConc
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
				msg, err := sitemonitor.BuildMonitorTaskMessage(ctx, session, &exec)
				if err != nil {
					e.failClaimedExecution(session, exec.ID, "构造监测载荷失败: "+err.Error())
					continue
				}
				payload, err := sitemonitor.MarshalMonitorPayload(msg)
				if err != nil {
					e.failClaimedExecution(session, exec.ID, "序列化监测载荷失败: "+err.Error())
					continue
				}

				now := time.Now()
				session.Model(&model.MonitorExecution{}).Where("id = ?", exec.ID).
					Update("started_at", now)

				e.scheduler.Submit(&agent.TaskEnvelope{
					ID:      exec.ID,
					Type:    "monitor",
					Payload: payload,
				})
			}
		}
	}
}

func (e *EmbeddedAgent) failClaimedExecution(session *gorm.DB, executionID, errMsg string) {
	now := time.Now()
	session.Model(&model.MonitorExecution{}).Where("id = ?", executionID).
		Updates(map[string]any{
			"status":      "failed",
			"error":       errMsg,
			"finished_at": now,
		})
}

func (e *EmbeddedAgent) saveResultToDB(session *gorm.DB, result *agent.TaskResult) {
	agentID := result.AgentID
	if agentID == "" {
		agentID = e.agentUUID
	}
	if err := sitemonitor.FinalizeFromTaskResult(
		context.Background(),
		session,
		result.ID,
		agentID,
		result.Status,
		result.Error,
		result.Result,
		result.StartedAt,
		result.FinishedAt,
	); err != nil {
		slog.Error("embedded monitor finalize failed", "execution_id", result.ID, "error", err)
		e.failClaimedExecution(session, result.ID, "结果落库失败: "+err.Error())
	}

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
