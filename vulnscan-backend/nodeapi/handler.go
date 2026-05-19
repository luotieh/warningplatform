package nodeapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"vulnscan-backend/agent"
	"vulnscan-backend/model"
	"vulnscan-backend/pkg/nodeauth"
	"vulnscan-backend/sitemonitor"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (a *NodeAPI) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ok": true, "service": "node-api"})
}

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

		secret := c.GetHeader("X-Agent-Secret")
		if secret == "" {
			secret = c.Query("agent_secret")
		}

		var node model.Node
		err := a.gdb().Where("uuid = ? AND status != ?", token, "disabled").First(&node).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "unknown agent token (主控中无此 node_uuid，请确认凭据由当前主控签发且未删节点)",
				})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid agent credentials"})
			return
		}

		if a.opts.RequireAgentSecret && node.AgentSecretHash == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "node agent secret not configured on server"})
			return
		}

		if node.AgentSecretHash != "" {
			if secret == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing X-Agent-Secret"})
				return
			}
			if !nodeauth.VerifySecret(secret, node.AgentSecretHash) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid agent secret (X-Agent-Secret 与主控记录不一致，请重新签发或解密最新凭据文件)",
				})
				return
			}
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

// Shutdown 扫描节点优雅退出时主动通知主控，立即标离线并回收未完成任务。
func (a *NodeAPI) Shutdown(c *gin.Context) {
	nodeUUID := c.GetString("node_uuid")

	var req agent.ShutdownReq
	if err := c.ShouldBindJSON(&req); err != nil && c.Request.ContentLength > 0 {
		web.Fail(c).Msg("invalid request").Send()
		return
	}

	now := time.Now()
	session := a.gdb()
	session.Model(&model.Node{}).Where("uuid = ?", nodeUUID).Updates(map[string]any{
		"status":         model.NodeStatusOffline,
		"running_tasks":  req.RunningTasks,
		"queued_tasks":   req.QueuedTasks,
		"last_heartbeat": now,
	})
	a.recoverNodeWorkload(session, nodeUUID, req.Reason)

	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "graceful"
	}
	slog.Info("[NodeAPI] 扫描节点主动下线",
		"node_uuid", nodeUUID,
		"reason", reason,
		"running_tasks", req.RunningTasks,
		"queued_tasks", req.QueuedTasks,
	)
	web.OK(c).Send()
}

func (a *NodeAPI) recoverNodeWorkload(session *gorm.DB, nodeUUID, reason string) {
	if nodeUUID == "" {
		return
	}
	msg := "节点已停止运行，任务重新排队"
	if r := strings.TrimSpace(reason); r != "" && r != "graceful" {
		msg = fmt.Sprintf("节点已停止运行（%s），任务重新排队", r)
	}

	session.Model(&model.ScanTask{}).
		Where("worker_id = ? AND status = ?", nodeUUID, model.TaskStatusRunning).
		Updates(map[string]any{
			"status":    model.TaskStatusQueued,
			"worker_id": "",
			"error_msg": msg,
		})

	session.Model(&model.MonitorExecution{}).
		Where("agent_id = ? AND status = ?", nodeUUID, "running").
		Updates(map[string]any{
			"status":   "pending",
			"agent_id": "",
		})
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
				msg, err := sitemonitor.BuildMonitorTaskMessage(context.Background(), session, &exec)
				if err != nil {
					continue
				}
				payload, err := sitemonitor.MarshalMonitorPayload(msg)
				if err != nil {
					continue
				}

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
		Where("worker_id = ? OR worker_id = '' OR worker_id IS NULL", nodeUUID).
		Order("priority DESC, created_at ASC").
		Limit(scanBatch).
		Find(&scanTasks)

	claimable := make([]model.ScanTask, 0, len(scanTasks))
	for _, st := range scanTasks {
		if !model.ScanTaskLocalExecutorOnly(st.Parameters) {
			claimable = append(claimable, st)
		}
	}
	scanTasks = claimable

	if len(scanTasks) > 0 {
		scanIDs := make([]string, len(scanTasks))
		for i, t := range scanTasks {
			scanIDs[i] = t.ID
		}

		res := session.Model(&model.ScanTask{}).
			Where("id IN ? AND status = ? AND (worker_id = ? OR worker_id = ? OR worker_id IS NULL)", scanIDs, model.TaskStatusQueued, nodeUUID, "").
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
			a.monitorResult.HandleMonitorResult(
				result.ID,
				result.AgentID,
				result.Status,
				result.Error,
				result.Result,
				result.StartedAt,
				result.FinishedAt,
			)
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
		if raw, ok := validRuleJSONRaw(r.Data); ok {
			ruleMap[r.ModuleKey] = raw
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

	payload, err := json.Marshal(struct {
		Rules map[string]json.RawMessage `json:"rules"`
	}{Rules: ruleMap})
	if err != nil {
		slog.Error("node-api rules marshal failed", "error", err)
		web.Fail(c).Err(fmt.Errorf("规则数据序列化失败: %w", err)).Send()
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", payload)
}

// validRuleJSONRaw 跳过空/空白或非法 JSON，避免 json.RawMessage 序列化导致响应体为空。
func validRuleJSONRaw(data string) (json.RawMessage, bool) {
	trimmed := strings.TrimSpace(data)
	if trimmed == "" {
		return nil, false
	}
	raw := json.RawMessage(trimmed)
	if !json.Valid(raw) {
		return nil, false
	}
	return raw, true
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
