package cluster

import (
	"math"
	"os"
	"runtime"
	"time"

	"code.yt-security.com/public/access/authorize"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

type UnifiedNode struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Type          string  `json:"type"`
	IP            string  `json:"ip"`
	Status        string  `json:"status"`
	Version       string  `json:"version"`
	CPUUsage      float64 `json:"cpu_usage"`
	MemUsage      float64 `json:"mem_usage"`
	ActiveTasks   int     `json:"active_tasks"`
	Capacity      int     `json:"capacity"`
	HealthScore   float64 `json:"health_score"`
	Region        string  `json:"region,omitempty"`
	Label         string  `json:"label,omitempty"`
	LastHeartbeat string  `json:"last_heartbeat"`
	RegisteredAt  string  `json:"registered_at"`

	Hostname      string  `json:"hostname,omitempty"`
	BandwidthMbps float64 `json:"bandwidth_mbps,omitempty"`
	AvgLatencyMs  float64 `json:"avg_latency_ms,omitempty"`
	SuccessTasks  int     `json:"success_tasks,omitempty"`
	FailedTasks   int     `json:"failed_tasks,omitempty"`

	QueuedTasks    int   `json:"queued_tasks,omitempty"`
	TasksCompleted int64 `json:"tasks_completed,omitempty"`
}

type LocalScheduler interface {
	ActiveTasks() int
	QueueLen() int
	MaxParallel() int
}

type nodesAPI struct {
	db        *gorm.DB
	scheduler LocalScheduler
}

func RegisterUnifiedNodeRoutes(g *gin.RouterGroup, db *gorm.DB, scheduler LocalScheduler) []authorize.BackendItem {
	api := &nodesAPI{db: db, scheduler: scheduler}
	return authorize.RegisterRoutes(g, []authorize.Route{
		{Name: "统一节点列表", Path: "nodes", Method: "GET", Handler: api.List, Enabled: true},
	})
}

func sanitizeFloat(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

func (a *nodesAPI) List(c *gin.Context) {
	nodeType := c.Query("type")
	status := c.Query("status")

	a.markStaleScanNodes()
	a.markStaleWorkerNodes()

	var nodes []UnifiedNode

	if nodeType == "" || nodeType == "local" {
		if local := a.buildLocalNode(); local != nil {
			if status == "" || status == local.Status {
				nodes = append(nodes, *local)
			}
		}
	}

	if nodeType == "" || nodeType == "worker" {
		nodes = append(nodes, a.loadWorkerNodes(status)...)
	}
	if nodeType == "" || nodeType == "agent" {
		nodes = append(nodes, a.loadAgentNodes(status)...)
	}
	if nodeType == "" || nodeType == "scan" {
		nodes = append(nodes, a.loadScanNodes(status)...)
	}

	summary := computeNodeSummary(nodes)

	web.Succeed(c).Data(gin.H{
		"nodes":   nodes,
		"summary": summary,
	}).Send()
}

const embeddedAgentUUID = "embedded-default"

// 与 agent 默认心跳间隔对齐（默认 10s，见 agent heartbeat_interval）。
const defaultAgentHeartbeatInterval = 10 * time.Second

const scanNodeOfflineGracePeriods = 3

// scanNodeOfflineTimeout：3 个心跳周期无上报则标为离线（崩溃/强杀等未走 /node-api/shutdown 的场景）。
const scanNodeOfflineTimeout = scanNodeOfflineGracePeriods * defaultAgentHeartbeatInterval

func (a *nodesAPI) buildLocalNode() *UnifiedNode {
	if a.scheduler == nil {
		return nil
	}

	hostname, _ := os.Hostname()
	activeTasks := a.scheduler.ActiveTasks()
	capacity := a.scheduler.MaxParallel()
	queueLen := a.scheduler.QueueLen()

	cpuPct := 0.0
	if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 {
		cpuPct = percents[0]
	}

	memPct := 0.0
	if v, err := mem.VirtualMemory(); err == nil {
		memPct = v.UsedPercent
	}

	// Merge embedded monitor agent stats
	var embeddedAgent model.MonitorAgent
	if err := a.db.Where("uuid = ?", embeddedAgentUUID).First(&embeddedAgent).Error; err == nil {
		activeTasks += embeddedAgent.RunningTasks
		capacity += embeddedAgent.MaxConcurrent
		queueLen += embeddedAgent.QueuedTasks
	}

	nodeStatus := "online"
	if capacity > 0 && activeTasks >= capacity {
		nodeStatus = "busy"
	}

	score := 100.0
	if capacity > 0 {
		score -= float64(activeTasks) / float64(capacity) * 40
	}
	if cpuPct > 50 {
		score -= (cpuPct - 50) * 0.4
	}
	if memPct > 50 {
		score -= (memPct - 50) * 0.3
	}
	if score < 0 {
		score = 0
	}

	return &UnifiedNode{
		ID:            "local",
		Name:          "本地执行引擎",
		Type:          "local",
		IP:            "127.0.0.1",
		Status:        nodeStatus,
		Version:       runtime.Version(),
		CPUUsage:      sanitizeFloat(cpuPct),
		MemUsage:      sanitizeFloat(memPct),
		ActiveTasks:   activeTasks,
		Capacity:      capacity,
		HealthScore:   sanitizeFloat(score),
		LastHeartbeat: time.Now().Format(time.RFC3339),
		Hostname:      hostname,
		QueuedTasks:   queueLen,
	}
}

func (a *nodesAPI) loadWorkerNodes(status string) []UnifiedNode {
	var workers []model.WorkerNode
	q := a.db.Model(&model.WorkerNode{})
	if status != "" {
		q = q.Where("status = ?", status)
	}
	q.Order("last_heartbeat DESC").Find(&workers)

	nodes := make([]UnifiedNode, 0, len(workers))
	for _, w := range workers {
		nodes = append(nodes, UnifiedNode{
			ID:            w.ID,
			Name:          w.Name,
			Type:          "worker",
			IP:            w.IP,
			Status:        w.Status,
			Version:       w.Version,
			CPUUsage:      sanitizeFloat(w.CPUUsage),
			MemUsage:      sanitizeFloat(w.MemUsage),
			ActiveTasks:   w.ActiveTasks,
			Capacity:      w.Capacity,
			HealthScore:   sanitizeFloat(w.HealthScore()),
			LastHeartbeat: formatNodeTime(w.LastHeartbeat),
			RegisteredAt:  formatNodeTime(w.RegisteredAt),
			Hostname:      w.Hostname,
			BandwidthMbps: sanitizeFloat(w.BandwidthMbps),
			AvgLatencyMs:  sanitizeFloat(w.AvgLatencyMs),
			SuccessTasks:  w.SuccessTaskCount,
			FailedTasks:   w.FailedTaskCount,
		})
	}
	return nodes
}

func (a *nodesAPI) markStaleScanNodes() {
	cutoff := time.Now().Add(-scanNodeOfflineTimeout)
	a.db.Model(&model.Node{}).
		Where("uuid != ?", embeddedAgentUUID).
		Where("status = ?", model.NodeStatusOnline).
		Where("last_heartbeat IS NULL OR last_heartbeat < ?", cutoff).
		Updates(map[string]any{
			"status":        model.NodeStatusOffline,
			"running_tasks": 0,
			"queued_tasks":  0,
		})
}

func (a *nodesAPI) markStaleWorkerNodes() {
	cutoff := time.Now().Add(-scanNodeOfflineGracePeriods * defaultAgentHeartbeatInterval)
	a.db.Model(&model.WorkerNode{}).
		Where("status = ? AND (last_heartbeat IS NULL OR last_heartbeat < ?)", model.WorkerStatusOnline, cutoff).
		Updates(map[string]any{
			"status":       model.WorkerStatusOffline,
			"active_tasks": 0,
		})
}

func (a *nodesAPI) loadScanNodes(status string) []UnifiedNode {
	var rows []model.Node
	// embedded-default 为主控内置监测执行引擎在 vs_nodes 的登记，统计已合并进 buildLocalNode，不在此重复展示
	q := a.db.Model(&model.Node{}).Where("uuid != ?", embeddedAgentUUID)
	if status != "" {
		q = q.Where("status = ?", status)
	}
	q.Order("updated_at DESC").Find(&rows)

	nodes := make([]UnifiedNode, 0, len(rows))
	for _, n := range rows {
		name := n.Label
		if name == "" {
			name = n.Hostname
		}
		if name == "" {
			name = n.UUID
		}
		var hb string
		if n.LastHeartbeat != nil {
			hb = n.LastHeartbeat.Format(time.RFC3339)
		}
		nodes = append(nodes, UnifiedNode{
			ID:             n.UUID,
			Name:           name,
			Type:           "scan",
			IP:             n.IPAddress,
			Status:         n.Status,
			Version:        n.Version,
			CPUUsage:       sanitizeFloat(n.CPUUsage),
			MemUsage:       sanitizeFloat(n.MemoryUsage),
			ActiveTasks:    n.RunningTasks,
			Capacity:       n.MaxConcurrent,
			HealthScore:    sanitizeFloat(computeScanNodeHealth(n)),
			Region:         n.Region,
			Label:          n.Label,
			LastHeartbeat:  hb,
			RegisteredAt:   n.CreatedAt.Format(time.RFC3339),
			QueuedTasks:    n.QueuedTasks,
			TasksCompleted: n.TasksCompleted,
		})
	}
	return nodes
}

func computeScanNodeHealth(n model.Node) float64 {
	if n.Status == model.NodeStatusOffline {
		return 0
	}
	score := 100.0
	if n.MaxConcurrent > 0 {
		score -= float64(n.RunningTasks) / float64(n.MaxConcurrent) * 30
	}
	if n.CPUUsage > 50 {
		score -= (n.CPUUsage - 50) * 0.4
	}
	if n.MemoryUsage > 50 {
		score -= (n.MemoryUsage - 50) * 0.3
	}
	if score < 0 {
		score = 0
	}
	return sanitizeFloat(score)
}

func (a *nodesAPI) loadAgentNodes(status string) []UnifiedNode {
	var agents []model.MonitorAgent
	q := a.db.Model(&model.MonitorAgent{}).Where("uuid != ?", embeddedAgentUUID)
	if status != "" {
		q = q.Where("status = ?", status)
	}
	q.Order("last_heartbeat DESC").Find(&agents)

	nodes := make([]UnifiedNode, 0, len(agents))
	for _, ag := range agents {
		name := ag.Label
		if name == "" {
			name = ag.UUID
		}

		var hb string
		if ag.LastHeartbeat != nil {
			hb = ag.LastHeartbeat.Format(time.RFC3339)
		}

		nodes = append(nodes, UnifiedNode{
			ID:             ag.UUID,
			Name:           name,
			Type:           "agent",
			IP:             ag.IPAddress,
			Status:         ag.Status,
			Version:        ag.Version,
			CPUUsage:       sanitizeFloat(ag.CPUUsage),
			MemUsage:       sanitizeFloat(ag.MemoryUsage),
			ActiveTasks:    ag.RunningTasks,
			Capacity:       ag.MaxConcurrent,
			HealthScore:    sanitizeFloat(computeAgentHealth(ag)),
			Region:         ag.Region,
			Label:          ag.Label,
			LastHeartbeat:  hb,
			RegisteredAt:   ag.CreatedAt.Format(time.RFC3339),
			QueuedTasks:    ag.QueuedTasks,
			TasksCompleted: ag.TasksCompleted,
		})
	}
	return nodes
}

func computeAgentHealth(a model.MonitorAgent) float64 {
	if a.Status == "offline" {
		return 0
	}
	score := 100.0
	if a.MaxConcurrent > 0 {
		score -= float64(a.RunningTasks) / float64(a.MaxConcurrent) * 30
	}
	if a.CPUUsage > 50 {
		score -= (a.CPUUsage - 50) * 0.4
	}
	if a.MemoryUsage > 50 {
		score -= (a.MemoryUsage - 50) * 0.3
	}
	if score < 0 {
		score = 0
	}
	return sanitizeFloat(score)
}

type NodeSummary struct {
	TotalNodes    int `json:"total_nodes"`
	OnlineNodes   int `json:"online_nodes"`
	OfflineNodes  int `json:"offline_nodes"`
	WorkerCount   int `json:"worker_count"`
	AgentCount    int `json:"agent_count"`
	TotalTasks    int `json:"total_tasks"`
	TotalCapacity int `json:"total_capacity"`
}

func computeNodeSummary(nodes []UnifiedNode) NodeSummary {
	s := NodeSummary{TotalNodes: len(nodes)}
	for _, n := range nodes {
		switch n.Type {
		case "worker":
			s.WorkerCount++
		case "agent":
			s.AgentCount++
		case "scan":
			s.WorkerCount++
		}
		if n.Status == "online" || n.Status == "busy" {
			s.OnlineNodes++
		} else if n.Status == "offline" {
			s.OfflineNodes++
		}
		s.TotalTasks += n.ActiveTasks
		s.TotalCapacity += n.Capacity
	}
	return s
}

func formatNodeTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
