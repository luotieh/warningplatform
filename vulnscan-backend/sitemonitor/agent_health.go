package sitemonitor

import (
	"context"
	"log/slog"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type AgentHealthChecker struct {
	db              *db.DB
	offlineTimeout  time.Duration
	checkInterval   time.Duration
	reassignTimeout time.Duration
	cancel          context.CancelFunc
	cleanupCfg      CleanupConfig
	lastCleanup     time.Time
}

func NewAgentHealthChecker(database *db.DB) *AgentHealthChecker {
	return &AgentHealthChecker{
		db:              database,
		offlineTimeout:  90 * time.Second,
		checkInterval:   60 * time.Second,
		reassignTimeout: 5 * time.Minute,
		cleanupCfg:      DefaultCleanupConfig(),
	}
}

func (h *AgentHealthChecker) SetCleanupConfig(cfg CleanupConfig) {
	h.cleanupCfg = cfg
}

func (h *AgentHealthChecker) GetCleanupConfig() CleanupConfig {
	return h.cleanupCfg
}

func (h *AgentHealthChecker) session() *gorm.DB {
	s, _ := h.db.GetDBSession()
	return s
}

func (h *AgentHealthChecker) Start(ctx context.Context) {
	ctx, h.cancel = context.WithCancel(ctx)

	go h.runLoop(ctx)
	slog.Info("[AgentHealth] checker started",
		"offline_timeout", h.offlineTimeout,
		"check_interval", h.checkInterval)
}

func (h *AgentHealthChecker) Stop() {
	if h.cancel != nil {
		h.cancel()
	}
}

func (h *AgentHealthChecker) runLoop(ctx context.Context) {
	ticker := time.NewTicker(h.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.checkAgents()
			h.reassignStuckTasks()
			if n, err := ExpireAllStaleExecutions(h.session()); err != nil {
				slog.Warn("[AgentHealth] expire stale executions failed", "error", err)
			} else if n > 0 {
				slog.Warn("[AgentHealth] expired stale monitor executions", "count", n)
			}
			if time.Since(h.lastCleanup) >= time.Hour {
				h.lastCleanup = time.Now()
				if n, err := CleanupOldExecutions(h.session(), h.cleanupCfg); err != nil {
					slog.Warn("[AgentHealth] cleanup old executions failed", "error", err)
				} else if n > 0 {
					slog.Info("[AgentHealth] cleaned up old executions", "count", n)
				}
			}
		}
	}
}

func (h *AgentHealthChecker) checkAgents() {
	cutoff := time.Now().Add(-h.offlineTimeout)

	result := h.session().
		Model(&model.MonitorAgent{}).
		Where("status = ? AND (last_heartbeat IS NULL OR last_heartbeat < ?)", "online", cutoff).
		Updates(map[string]any{"status": "offline"})

	if result.RowsAffected > 0 {
		slog.Warn("[AgentHealth] agents marked offline",
			"count", result.RowsAffected,
			"cutoff", cutoff.Format(time.RFC3339))
	}
}

func (h *AgentHealthChecker) reassignStuckTasks() {
	cutoff := time.Now().Add(-h.reassignTimeout)

	var stuckExecs []model.MonitorExecution
	h.session().
		Where("status = ? AND created_at < ?", "running", cutoff).
		Select("id, agent_id").
		Find(&stuckExecs)

	if len(stuckExecs) == 0 {
		return
	}

	// batch-load online agent IDs to avoid per-row queries
	agentIDs := make([]string, 0)
	for _, exec := range stuckExecs {
		if exec.AgentID != "" {
			agentIDs = append(agentIDs, exec.AgentID)
		}
	}
	onlineAgents := make(map[string]bool)
	if len(agentIDs) > 0 {
		var agents []model.MonitorAgent
		h.session().Where("uuid IN ? AND status = ?", agentIDs, "online").
			Select("uuid").Find(&agents)
		for _, a := range agents {
			onlineAgents[a.UUID] = true
		}
	}

	reassignIDs := make([]string, 0)
	for _, exec := range stuckExecs {
		if exec.AgentID != "" && onlineAgents[exec.AgentID] {
			continue
		}
		reassignIDs = append(reassignIDs, exec.ID)
	}

	if len(reassignIDs) == 0 {
		return
	}

	const batchSize = 500
	for i := 0; i < len(reassignIDs); i += batchSize {
		end := i + batchSize
		if end > len(reassignIDs) {
			end = len(reassignIDs)
		}
		h.session().Model(&model.MonitorExecution{}).
			Where("id IN ?", reassignIDs[i:end]).
			Updates(map[string]any{
				"status":   "pending",
				"agent_id": "",
				"error":    "任务因Agent离线被重新分配",
			})
	}

	slog.Info("[AgentHealth] tasks reassigned", "count", len(reassignIDs))
}
