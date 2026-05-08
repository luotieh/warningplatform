package model

import "time"

type WorkerNode struct {
	ID          string  `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name        string  `gorm:"type:varchar(200)" json:"name"`
	Hostname    string  `gorm:"type:varchar(200)" json:"hostname"`
	IP          string  `gorm:"type:varchar(45)" json:"ip"`
	Port        int     `gorm:"default:0" json:"port"`
	Version     string  `gorm:"type:varchar(50)" json:"version"`
	Status      string  `gorm:"type:varchar(20);index;default:'offline'" json:"status"`
	Capacity    int     `gorm:"default:10" json:"capacity"`
	ActiveTasks int     `gorm:"default:0" json:"active_tasks"`
	CPUUsage    float64 `gorm:"default:0" json:"cpu_usage"`
	MemUsage    float64 `gorm:"default:0" json:"mem_usage"`

	BandwidthMbps     float64     `gorm:"default:0" json:"bandwidth_mbps"`
	AvgLatencyMs      float64     `gorm:"default:0" json:"avg_latency_ms"`
	ProxyHealthyCount int         `gorm:"default:0" json:"proxy_healthy_count"`
	ProxyTotalCount   int         `gorm:"default:0" json:"proxy_total_count"`
	FailedTaskCount   int         `gorm:"default:0" json:"failed_task_count"`
	SuccessTaskCount  int         `gorm:"default:0" json:"success_task_count"`
	BannedTargets     StringArray `gorm:"type:text" json:"banned_targets"`

	Tags          StringArray `gorm:"type:text" json:"tags"`
	LastHeartbeat time.Time   `gorm:"index" json:"last_heartbeat"`
	RegisteredAt  time.Time   `json:"registered_at"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

func (WorkerNode) TableName() string { return "vs_worker_node" }

const (
	WorkerStatusOnline  = "online"
	WorkerStatusOffline = "offline"
	WorkerStatusBusy    = "busy"
	WorkerStatusDrain   = "drain"
)

// EffectiveCapacity returns dynamic capacity based on actual resource usage.
// Reduces capacity when CPU/Mem/Latency is high.
func (w *WorkerNode) EffectiveCapacity() int {
	cap := w.Capacity
	if cap <= 0 {
		return 0
	}

	if w.CPUUsage > 90 {
		cap = cap / 4
	} else if w.CPUUsage > 70 {
		cap = cap / 2
	}

	if w.MemUsage > 90 {
		cap = cap / 4
	} else if w.MemUsage > 70 {
		cap = cap / 2
	}

	if w.AvgLatencyMs > 5000 {
		cap = cap / 2
	}

	if cap < 1 {
		cap = 1
	}
	return cap
}

// LoadRatio returns the load ratio (0.0 ~ 1.0+) based on effective capacity.
func (w *WorkerNode) LoadRatio() float64 {
	ec := w.EffectiveCapacity()
	if ec <= 0 {
		return 1.0
	}
	return float64(w.ActiveTasks) / float64(ec)
}

// HealthScore returns a 0-100 score for worker selection (higher is better).
func (w *WorkerNode) HealthScore() float64 {
	score := 100.0

	score -= w.LoadRatio() * 40

	if w.CPUUsage > 50 {
		score -= (w.CPUUsage - 50) * 0.4
	}
	if w.MemUsage > 50 {
		score -= (w.MemUsage - 50) * 0.3
	}

	if w.AvgLatencyMs > 100 {
		penalty := (w.AvgLatencyMs - 100) / 100
		if penalty > 20 {
			penalty = 20
		}
		score -= penalty
	}

	if w.ProxyTotalCount > 0 {
		healthyRatio := float64(w.ProxyHealthyCount) / float64(w.ProxyTotalCount)
		score -= (1 - healthyRatio) * 10
	}

	totalTasks := w.SuccessTaskCount + w.FailedTaskCount
	if totalTasks > 0 {
		failRatio := float64(w.FailedTaskCount) / float64(totalTasks)
		score -= failRatio * 15
	}

	if score < 0 {
		score = 0
	}
	return score
}
