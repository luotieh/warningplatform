package monitoragent

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type EmbeddedAgent struct {
	db        *db.DB
	agent     *Agent
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

	var agent model.MonitorAgent
	err = session.Where("uuid = ?", e.agentUUID).First(&agent).Error
	if err != nil {
		agent = model.MonitorAgent{
			UUID:          e.agentUUID,
			Status:        "online",
			Version:       AgentVersion,
			MacAddress:    "local",
			IPAddress:     "127.0.0.1",
			MaxConcurrent: 5,
			MaxQueue:      100,
		}
		agent.ID = e.agentUUID
		if createErr := session.Create(&agent).Error; createErr != nil {
			slog.Error("embedded agent: create failed", "error", createErr)
		} else {
			slog.Info("embedded agent registered", "uuid", e.agentUUID)
		}
	} else {
		now := time.Now()
		result := session.Model(&model.MonitorAgent{}).
			Where("uuid = ?", e.agentUUID).
			Updates(map[string]any{
				"status":         "online",
				"version":        AgentVersion,
				"last_heartbeat": now,
				"max_concurrent": 5,
				"max_queue":      100,
				"ip_address":     "127.0.0.1",
				"mac_address":    "local",
			})
		slog.Info("embedded agent status updated",
			"uuid", e.agentUUID,
			"rows_affected", result.RowsAffected,
			"error", result.Error)
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel

	e.wg.Add(1)
	go e.runDirectLoop(ctx, session)

	slog.Info("embedded agent started",
		"uuid", e.agentUUID,
		"concurrency", 5)
}

func (e *EmbeddedAgent) runDirectLoop(ctx context.Context, session *gorm.DB) {
	defer e.wg.Done()

	ps := NewPageService()
	sched := NewScheduler(ps, 5, 5*time.Minute)

	rules := &MemoryRuleStore{data: make(map[string][]byte)}
	e.loadRulesFromDB(session, rules)

	sched.RegisterEngine(&AvailabilityEngine{Rules: rules})
	sched.RegisterEngine(&TamperEngine{Rules: rules})
	sched.RegisterEngine(&BlacklinkEngine{Rules: rules})
	sched.RegisterEngine(&SensitiveWordEngine{Rules: rules})
	sched.RegisterEngine(&SensitiveFileEngine{Rules: rules})
	sched.RegisterEngine(&DomainHijackEngine{Rules: rules})

	sched.SetResultCallback(func(result *TaskResult) {
		result.AgentID = e.agentUUID
		e.saveResultToDB(session, result)
	})

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	heartbeatTicker := time.NewTicker(15 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			sched.WaitWithTimeout(30 * time.Second)
			ps.Close()
			return
		case <-heartbeatTicker.C:
			session.Model(&model.MonitorAgent{}).
				Where("uuid = ?", e.agentUUID).
				Updates(map[string]any{
					"status":         "online",
					"last_heartbeat": time.Now(),
					"running_tasks":  sched.RunningCount(),
					"queued_tasks":   sched.QueuedCount(),
					"max_concurrent": 5,
					"max_queue":      100,
				})
		case <-ticker.C:
			available := 5 - sched.RunningCount() - sched.QueuedCount()
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

				msg := TaskMessage{
					ExecutionID: exec.ID,
					TaskID:      task.ID,
					Dimension:   exec.Dimension,
					URL:         task.TargetHomepage,
				}

				sched.Submit(&msg)
			}
		}
	}
}

func (e *EmbeddedAgent) saveResultToDB(session *gorm.DB, result *TaskResult) {
	startedAt := parseTimeStr(result.StartedAt)
	finishedAt := parseTimeStr(result.FinishedAt)

	updates := map[string]any{
		"status":      result.Status,
		"error":       result.Error,
		"result_json": result.Result,
		"started_at":  startedAt,
		"finished_at": finishedAt,
	}

	var hasIssue bool
	switch result.Dimension {
	case "availability":
		hasIssue = !jsonFieldBool(result.Result, "available")
	case "tamper":
		hasIssue = jsonFieldBool(result.Result, "tampered")
	case "blacklink":
		hasIssue = jsonFieldBool(result.Result, "has_black")
	case "sensitive_word":
		hasIssue = jsonFieldBool(result.Result, "has_hit")
	case "sensitive_file":
		hasIssue = jsonFieldBool(result.Result, "has_hit")
	case "domain_hijack":
		hasIssue = jsonFieldBool(result.Result, "hijacked")
	}

	updates["has_issue"] = hasIssue
	if hasIssue {
		updates["disposition"] = model.MonitorDispositionPending
	} else {
		updates["disposition"] = model.MonitorDispositionValid
	}

	session.Model(&model.MonitorExecution{}).
		Where("id = ?", result.ExecutionID).
		Updates(updates)

	session.Model(&model.MonitorAgent{}).
		Where("uuid = ?", e.agentUUID).
		UpdateColumn("tasks_completed", gorm.Expr("tasks_completed + 1"))

	if result.Dimension == "availability" && result.Status == "success" {
		e.updatePerfBaseline(session, result)
	}
}

func (e *EmbeddedAgent) loadRulesFromDB(session *gorm.DB, store *MemoryRuleStore) {
	var rules []model.MonitorRuleData
	session.Find(&rules)

	store.mu.Lock()
	for _, r := range rules {
		if r.Data != "" {
			store.data[r.ModuleKey] = []byte(r.Data)
		}
	}
	store.mu.Unlock()

	slog.Info("embedded agent: rules loaded from DB", "count", len(rules))
}

func (e *EmbeddedAgent) updatePerfBaseline(session *gorm.DB, result *TaskResult) {
	var m map[string]any
	if err := json.Unmarshal([]byte(result.Result), &m); err != nil {
		return
	}

	timing, _ := m["timing"].(map[string]any)
	if timing == nil {
		return
	}

	dnsMS, _ := timing["dns_ms"].(float64)
	ttfbMS, _ := timing["ttfb_ms"].(float64)
	totalMS, _ := timing["total_ms"].(float64)

	httpInfo, _ := m["http"].(map[string]any)
	contentLen := 0
	if httpInfo != nil {
		if cl, ok := httpInfo["content_length"].(float64); ok {
			contentLen = int(cl)
		}
	}

	var baseline model.MonitorPerfBaseline
	err := session.Where("task_id = ?", result.TaskID).First(&baseline).Error
	if err != nil {
		baseline = model.MonitorPerfBaseline{
			ID:            result.TaskID,
			TaskID:        result.TaskID,
			AvgDNSMS:      dnsMS,
			AvgTTFBMS:     ttfbMS,
			AvgTotalMS:    totalMS,
			AvgContentLen: contentLen,
			SampleCount:   1,
			P95TotalMS:    totalMS,
			MaxTotalMS:    totalMS,
			MinTotalMS:    totalMS,
			UpdatedAt:     time.Now(),
		}
		session.Create(&baseline)
		return
	}

	alpha := 0.2 // EWMA
	baseline.AvgDNSMS = baseline.AvgDNSMS*(1-alpha) + dnsMS*alpha
	baseline.AvgTTFBMS = baseline.AvgTTFBMS*(1-alpha) + ttfbMS*alpha
	baseline.AvgTotalMS = baseline.AvgTotalMS*(1-alpha) + totalMS*alpha
	baseline.AvgContentLen = int(float64(baseline.AvgContentLen)*(1-alpha) + float64(contentLen)*alpha)
	baseline.SampleCount++

	if totalMS > baseline.MaxTotalMS {
		baseline.MaxTotalMS = totalMS
	}
	if totalMS < baseline.MinTotalMS || baseline.MinTotalMS == 0 {
		baseline.MinTotalMS = totalMS
	}
	baseline.P95TotalMS = baseline.P95TotalMS*(1-0.05) + totalMS*0.05
	baseline.UpdatedAt = time.Now()

	session.Save(&baseline)
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
	}

	e.wg.Wait()
	slog.Info("embedded agent stopped")
}

func parseTimeStr(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

func jsonFieldBool(raw string, key string) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}
