package cluster

import (
	"os"
	"runtime"
	"time"

	"code.yt-security.com/public/core/v2/web"
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

func RegisterUnifiedNodeRoutes(g *gin.RouterGroup, db *gorm.DB, scheduler LocalScheduler) {
	api := &nodesAPI{db: db, scheduler: scheduler}
	g.GET("/nodes", api.List)
}

func (a *nodesAPI) List(c *gin.Context) {
	nodeType := c.Query("type")
	status := c.Query("status")

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

	summary := computeNodeSummary(nodes)

	web.OK(c).Data(gin.H{
		"nodes":   nodes,
		"summary": summary,
	}).Send()
}

const embeddedAgentUUID = "embedded-default"

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
		CPUUsage:      cpuPct,
		MemUsage:      memPct,
		ActiveTasks:   activeTasks,
		Capacity:      capacity,
		HealthScore:   score,
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
			CPUUsage:      w.CPUUsage,
			MemUsage:      w.MemUsage,
			ActiveTasks:   w.ActiveTasks,
			Capacity:      w.Capacity,
			HealthScore:   w.HealthScore(),
			LastHeartbeat: formatNodeTime(w.LastHeartbeat),
			RegisteredAt:  formatNodeTime(w.RegisteredAt),
			Hostname:      w.Hostname,
			BandwidthMbps: w.BandwidthMbps,
			AvgLatencyMs:  w.AvgLatencyMs,
			SuccessTasks:  w.SuccessTaskCount,
			FailedTasks:   w.FailedTaskCount,
		})
	}
	return nodes
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
			CPUUsage:       ag.CPUUsage,
			MemUsage:       ag.MemoryUsage,
			ActiveTasks:    ag.RunningTasks,
			Capacity:       ag.MaxConcurrent,
			HealthScore:    computeAgentHealth(ag),
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
	return score
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
