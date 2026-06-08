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
}

func NewAgentHealthChecker(database *db.DB) *AgentHealthChecker {
	return &AgentHealthChecker{
		db:              database,
		offlineTimeout:  90 * time.Second,
		checkInterval:   30 * time.Second,
		reassignTimeout: 5 * time.Minute,
	}
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
		Find(&stuckExecs)

	if len(stuckExecs) == 0 {
		return
	}

	for _, exec := range stuckExecs {
		var agent model.MonitorAgent
		if exec.AgentID != "" {
			if err := h.session().Where("uuid = ?", exec.AgentID).First(&agent).Error; err == nil {
				if agent.Status == "online" {
					continue
				}
			}
		}

		h.session().Model(&model.MonitorExecution{}).
			Where("id = ?", exec.ID).
			Updates(map[string]any{
				"status":   "pending",
				"agent_id": "",
				"error":    "任务因Agent离线被重新分配",
			})

		slog.Info("[AgentHealth] task reassigned",
			"execution_id", exec.ID,
			"old_agent", exec.AgentID)
	}
}
