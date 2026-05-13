package nodeapi

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"vulnscan-backend/agent"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (a *NodeAPI) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("X-Agent-Token")
		if token == "" {
			token = c.Query("token")
		}
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing agent token"})
			return
		}

		var node model.Node
		err := a.gdb().Where("uuid = ? AND status != ?", token, "disabled").First(&node).Error
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid agent token"})
			return
		}

		c.Set("node_uuid", node.UUID)
		c.Set("node_id", node.ID)
		c.Next()
	}
}

func (a *NodeAPI) Heartbeat(c *gin.Context) {
	nodeUUID := c.GetString("node_uuid")

	var req agent.HeartbeatReq
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Fail(c).Msg("invalid request").Send()
		return
	}

	now := time.Now()
	updates := map[string]any{
		"status":         model.NodeStatusOnline,
		"last_heartbeat": now,
		"running_tasks":  req.RunningTasks,
		"queued_tasks":   req.QueuedTasks,
		"max_concurrent": req.MaxConcurrent,
		"cpu_usage":      req.CPUUsage,
		"memory_usage":   req.MemoryUsage,
		"ip_address":     req.IPAddress,
		"mac_address":    req.MacAddress,
	}
	if req.Version != "" {
		updates["version"] = req.Version
	}

	a.gdb().Model(&model.Node{}).Where("uuid = ?", nodeUUID).Updates(updates)
	web.OK(c).Send()
}

func (a *NodeAPI) PollTasks(c *gin.Context) {
	nodeUUID := c.GetString("node_uuid")

	batch := 5
	if b := c.Query("batch"); b != "" {
		fmt.Sscanf(b, "%d", &batch)
		if batch <= 0 || batch > 20 {
			batch = 5
		}
	}

	timeout := 30 * time.Second
	if t := c.Query("timeout"); t != "" {
		if d, err := time.ParseDuration(t); err == nil && d > 0 && d <= 60*time.Second {
			timeout = d
		}
	}

	deadline := time.Now().Add(timeout)
	pollInterval := 2 * time.Second

	for time.Now().Before(deadline) {
		tasks := a.pollBothTaskTypes(nodeUUID, batch)
		if len(tasks) > 0 {
			c.JSON(http.StatusOK, gin.H{"tasks": tasks})
			return
		}

		select {
		case <-c.Request.Context().Done():
			c.JSON(http.StatusOK, gin.H{"tasks": []any{}})
			return
		case <-time.After(pollInterval):
		}
	}

	c.JSON(http.StatusOK, gin.H{"tasks": []any{}})
}

func (a *NodeAPI) pollBothTaskTypes(nodeUUID string, batch int) []agent.TaskEnvelope {
	var tasks []agent.TaskEnvelope
	session := a.gdb()

	// Poll monitor executions
	monitorBatch := batch / 2
	if monitorBatch < 1 {
		monitorBatch = 1
	}
	var executions []model.MonitorExecution
	session.
		Where("status = ? AND (agent_id IS NULL OR agent_id = '')", "pending").
		Order("created_at ASC").
		Limit(monitorBatch).
		Find(&executions)

	if len(executions) > 0 {
		ids := make([]string, len(executions))
		for i, ex := range executions {
			ids[i] = ex.ID
		}

		res := session.Model(&model.MonitorExecution{}).
			Where("id IN ? AND (agent_id IS NULL OR agent_id = '')", ids).
			Updates(map[string]any{"agent_id": nodeUUID, "status": "running"})

		if res.RowsAffected > 0 {
			session.Where("id IN ? AND agent_id = ?", ids, nodeUUID).Find(&executions)
			for _, exec := range executions {
				var task model.MonitorTask
				if err := session.First(&task, "id = ?", exec.TaskID).Error; err != nil {
					continue
				}

				payload, _ := json.Marshal(map[string]any{
					"execution_id": exec.ID,
					"task_id":      task.ID,
					"dimension":    exec.Dimension,
					"url":          task.TargetHomepage,
				})

				tasks = append(tasks, agent.TaskEnvelope{
					ID:      exec.ID,
					Type:    "monitor",
					Payload: payload,
				})
			}
		}
	}

	// Poll scan tasks
	scanBatch := batch - len(tasks)
	if scanBatch < 1 {
		scanBatch = 1
	}
	var scanTasks []model.ScanTask
	session.
		Where("status = ?", model.TaskStatusQueued).
		Order("priority DESC, created_at ASC").
		Limit(scanBatch).
		Find(&scanTasks)

	if len(scanTasks) > 0 {
		scanIDs := make([]string, len(scanTasks))
		for i, t := range scanTasks {
			scanIDs[i] = t.ID
		}

		res := session.Model(&model.ScanTask{}).
			Where("id IN ? AND status = ?", scanIDs, model.TaskStatusQueued).
			Updates(map[string]any{"status": model.TaskStatusRunning, "worker_id": nodeUUID})

		if res.RowsAffected > 0 {
			session.Where("id IN ? AND worker_id = ?", scanIDs, nodeUUID).Find(&scanTasks)
			for _, st := range scanTasks {
				payload, _ := json.Marshal(map[string]any{
					"task_id":    st.ID,
					"targets":    st.Targets,
					"type":       st.Type,
					"config":     st.Config,
					"parameters": st.Parameters,
				})

				tasks = append(tasks, agent.TaskEnvelope{
					ID:       st.ID,
					Type:     "scan",
					Priority: st.Priority,
					Payload:  payload,
				})
			}
		}
	}

	return tasks
}

func (a *NodeAPI) ReportResult(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		web.Fail(c).Msg("read body failed").Send()
		return
	}

	var result agent.TaskResult
	if err := json.Unmarshal(body, &result); err != nil {
		web.Fail(c).Msg("invalid result").Send()
		return
	}

	switch result.Type {
	case "monitor":
		if a.monitorResult != nil {
			a.monitorResult.HandleMonitorResult(result.ID, result.Status, result.Error, result.Result, result.StartedAt, result.FinishedAt)
		}
	case "scan":
		if a.scanResult != nil {
			var finishedAt *time.Time
			if result.FinishedAt != "" {
				if t, err := time.Parse(time.RFC3339, result.FinishedAt); err == nil {
					finishedAt = &t
				}
			}
			a.scanResult.HandleScanResult(result.ID, result.Status, result.Error, 100, result.Result, finishedAt)
		}
	default:
		slog.Warn("unknown result type", "type", result.Type, "id", result.ID)
	}

	// Update node task counter
	a.gdb().Model(&model.Node{}).
		Where("uuid = ?", result.AgentID).
		UpdateColumn("tasks_completed", gorm.Expr("tasks_completed + 1"))

	web.OK(c).Send()
}

func (a *NodeAPI) GetRules(c *gin.Context) {
	session := a.gdb()

	var rules []model.MonitorRuleData
	if err := session.Find(&rules).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	ruleMap := make(map[string]json.RawMessage, len(rules))
	for _, r := range rules {
		if r.Data != "" {
			ruleMap[r.ModuleKey] = json.RawMessage(r.Data)
		}
	}

	var wordLibs []model.MonitorWordLibrary
	session.Find(&wordLibs)

	for _, lib := range wordLibs {
		var cats []model.MonitorWordCategory
		session.Where("library_id = ?", lib.ID).Find(&cats)

		type entryOut struct {
			Word     string `json:"word"`
			Severity string `json:"severity"`
		}
		type catOut struct {
			Name    string     `json:"name"`
			Entries []entryOut `json:"entries"`
		}

		categories := make([]catOut, 0, len(cats))
		for _, cat := range cats {
			var entries []model.MonitorWordEntry
			session.Where("category_id = ?", cat.ID).Find(&entries)
			eo := make([]entryOut, 0, len(entries))
			for _, e := range entries {
				eo = append(eo, entryOut{Word: e.Word, Severity: e.Severity})
			}
			categories = append(categories, catOut{Name: cat.Name, Entries: eo})
		}

		key := fmt.Sprintf("lib/word/%s", lib.ID)
		raw, _ := json.Marshal(map[string]any{
			"id":         lib.ID,
			"name":       lib.Name,
			"categories": categories,
		})
		ruleMap[key] = raw
	}

	var fileLibs []model.MonitorFileLibrary
	session.Find(&fileLibs)

	for _, lib := range fileLibs {
		var entries []model.MonitorFileEntry
		session.Where("library_id = ?", lib.ID).Find(&entries)

		key := fmt.Sprintf("lib/file/%s", lib.ID)
		raw, _ := json.Marshal(map[string]any{
			"id":      lib.ID,
			"name":    lib.Name,
			"entries": entries,
		})
		ruleMap[key] = raw
	}

	c.JSON(http.StatusOK, gin.H{"rules": ruleMap})
}

func (a *NodeAPI) PollCommands(c *gin.Context) {
	timeout := 30 * time.Second
	if t := c.Query("timeout"); t != "" {
		if d, err := time.ParseDuration(t); err == nil && d > 0 && d <= 60*time.Second {
			timeout = d
		}
	}

	select {
	case <-c.Request.Context().Done():
	case <-time.After(timeout):
	}

	c.JSON(http.StatusOK, gin.H{"commands": []any{}})
}
