package sitemonitor

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AgentAPI struct {
	db      *db.DB
	svc     *serviceMonitor
	mu      sync.RWMutex
	pending map[string][]model.MonitorTaskMessage
}

func NewAgentAPI(database *db.DB, svc *serviceMonitor) *AgentAPI {
	return &AgentAPI{
		db:      database,
		svc:     svc,
		pending: make(map[string][]model.MonitorTaskMessage),
	}
}

func (a *AgentAPI) gdb() *gorm.DB {
	s, _ := a.db.GetDBSession()
	return s
}

func (a *AgentAPI) RegisterRoutes(e *gin.Engine, pathPrefix string) {
	g := e.Group(pathPrefix + "/agent-api")
	g.Use(a.authMiddleware())

	g.POST("/heartbeat", a.Heartbeat)
	g.GET("/tasks/poll", a.PollTasks)
	g.POST("/tasks/result", a.ReportResult)
	g.GET("/rules", a.GetRules)
	g.POST("/evidence/upload", a.UploadEvidence)
	g.GET("/commands/poll", a.PollCommands)
}

func (a *AgentAPI) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("X-Agent-Token")
		if token == "" {
			token = c.Query("token")
		}
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "missing agent token"})
			return
		}

		var agent model.MonitorAgent
		err := a.gdb().Where("uuid = ? AND status != ?", token, "disabled").
			First(&agent).Error
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "invalid agent token"})
			return
		}

		c.Set("agent_uuid", agent.UUID)
		c.Set("agent_id", agent.ID)
		c.Next()
	}
}

func (a *AgentAPI) Heartbeat(c *gin.Context) {
	agentUUID := c.GetString("agent_uuid")

	var req struct {
		RunningTasks  int     `json:"running_tasks"`
		QueuedTasks   int     `json:"queued_tasks"`
		MaxConcurrent int     `json:"max_concurrent"`
		MaxQueue      int     `json:"max_queue"`
		CPUUsage      float64 `json:"cpu_usage"`
		MemoryUsage   float64 `json:"memory_usage"`
		Version       string  `json:"version"`
		MacAddress    string  `json:"mac_address"`
		IPAddress     string  `json:"ip_address"`
		Region        string  `json:"region"`
		Label         string  `json:"label"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	now := time.Now()
	updates := map[string]any{
		"status":         "online",
		"last_heartbeat": now,
		"running_tasks":  req.RunningTasks,
		"queued_tasks":   req.QueuedTasks,
		"max_concurrent": req.MaxConcurrent,
		"max_queue":      req.MaxQueue,
		"cpu_usage":      req.CPUUsage,
		"memory_usage":   req.MemoryUsage,
		"ip_address":     req.IPAddress,
		"mac_address":    req.MacAddress,
	}
	if req.Version != "" {
		updates["version"] = req.Version
	}
	if req.Region != "" {
		updates["region"] = req.Region
	}
	if req.Label != "" {
		updates["label"] = req.Label
	}

	a.gdb().Model(&model.MonitorAgent{}).
		Where("uuid = ?", agentUUID).
		Updates(updates)

	web.Resp(c, web.Success)
}

func (a *AgentAPI) PollTasks(c *gin.Context) {
	agentUUID := c.GetString("agent_uuid")

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
		session := a.gdb()

		var executions []model.MonitorExecution
		err := session.
			Where("status = ? AND (agent_id IS NULL OR agent_id = '')", "pending").
			Order("created_at ASC").
			Limit(batch).
			Find(&executions).Error
		if err != nil {
			web.Resp(c, web.InternalError)
			return
		}

		if len(executions) > 0 {
			ids := make([]string, len(executions))
			for i, e := range executions {
				ids[i] = e.ID
			}

			result := session.Model(&model.MonitorExecution{}).
				Where("id IN ? AND (agent_id IS NULL OR agent_id = '')", ids).
				Updates(map[string]any{
					"agent_id": agentUUID,
					"status":   "assigned",
				})
			if result.RowsAffected == 0 {
				continue
			}

			session.Where("id IN ? AND agent_id = ?", ids, agentUUID).
				Find(&executions)

			tasks := make([]model.MonitorTaskMessage, 0, len(executions))
			for _, exec := range executions {
				var task model.MonitorTask
				if err := session.First(&task, "id = ?", exec.TaskID).Error; err != nil {
					continue
				}

				msg := model.MonitorTaskMessage{
					ExecutionID: exec.ID,
					TaskID:      task.ID,
					Dimension:   exec.Dimension,
					URL:         task.TargetHomepage,
				}

				if exec.Dimension == "tamper" {
					var baseline model.MonitorBaseline
					if err := session.
						Where("url_hash = ? AND is_active = ?",
							task.ID, true).
						First(&baseline).Error; err == nil {
						msg.Baseline = &model.MonitorBaselineMetadata{
							Version:           baseline.Version,
							Simhash:           baseline.Simhash,
							ContentHash:       baseline.ContentHash,
							DomStructureHash:  baseline.DomStructureHash,
							VisualHash:        baseline.VisualHash,
							Title:             baseline.Title,
							StatusCode:        baseline.StatusCode,
							VisibleTextLength: baseline.VisibleTextLength,
						}
					}
				}

				tasks = append(tasks, msg)
			}

			c.JSON(http.StatusOK, gin.H{
				"tasks": tasks,
				"count": len(tasks),
			})
			return
		}

		select {
		case <-c.Request.Context().Done():
			c.JSON(http.StatusOK, gin.H{"tasks": []any{}, "count": 0})
			return
		case <-time.After(pollInterval):
		}
	}

	c.JSON(http.StatusOK, gin.H{"tasks": []any{}, "count": 0})
}

func (a *AgentAPI) ReportResult(c *gin.Context) {
	var req model.MonitorAgentResult
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if req.ExecutionID == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if a.svc != nil {
		a.svc.HandleAgentResult(c.Request.Context(), &req)
	} else {
		slog.Warn("sitemonitor service is nil, cannot handle result",
			"execution_id", req.ExecutionID)
	}

	web.Resp(c, web.Success)
}

func (a *AgentAPI) GetRules(c *gin.Context) {
	session := a.gdb()

	var rules []model.MonitorRuleData
	if err := session.Find(&rules).Error; err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	ruleMap := make(map[string]json.RawMessage, len(rules))
	for _, r := range rules {
		if r.Data != "" {
			ruleMap[r.ModuleKey] = json.RawMessage(r.Data)
		}
	}

	var wordLibs []model.MonitorWordLibrary
	session.Preload("Categories", func(db *gorm.DB) *gorm.DB {
		return db.Preload("Entries")
	}).Find(&wordLibs)

	for _, lib := range wordLibs {
		key := fmt.Sprintf("lib/word/%s", lib.ID)
		raw, _ := json.Marshal(lib)
		ruleMap[key] = raw
	}

	var fileLibs []model.MonitorFileLibrary
	session.Preload("Entries").Find(&fileLibs)

	for _, lib := range fileLibs {
		key := fmt.Sprintf("lib/file/%s", lib.ID)
		raw, _ := json.Marshal(lib)
		ruleMap[key] = raw
	}

	c.JSON(http.StatusOK, gin.H{"rules": ruleMap})
}

func (a *AgentAPI) UploadEvidence(c *gin.Context) {
	executionID := c.PostForm("execution_id")
	evidenceType := c.PostForm("type")
	if executionID == "" || evidenceType == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	_ = header
	_ = data

	slog.Info("evidence uploaded",
		"execution_id", executionID,
		"type", evidenceType,
		"size", len(data))

	web.Resp(c, web.Success)
}

func (a *AgentAPI) PollCommands(c *gin.Context) {
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
