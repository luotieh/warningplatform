package model

import "time"

type Node struct {
	ID                 string `gorm:"primarykey;type:varchar(64)" json:"id"`
	UUID               string `gorm:"type:varchar(64);uniqueIndex" json:"uuid"`
	MachineFingerprint string `gorm:"type:varchar(128);index" json:"-"`
	// AgentSecretHash is a bcrypt hash of the node agent plaintext secret (X-Agent-Secret).
	// Empty means legacy mode: only X-Agent-Token (uuid) is checked unless global require flag is set.
	AgentSecretHash string     `gorm:"type:varchar(128);default:''" json:"-"`
	Status          string     `gorm:"type:varchar(20);default:offline;index" json:"status"`
	Version         string     `gorm:"type:varchar(50)" json:"version"`
	IPAddress       string     `gorm:"type:varchar(45)" json:"ip_address"`
	MacAddress      string     `gorm:"type:varchar(20)" json:"mac_address"`
	Hostname        string     `gorm:"type:varchar(200)" json:"hostname"`
	Region          string     `gorm:"type:varchar(50);index" json:"region"`
	Label           string     `gorm:"type:varchar(200)" json:"label"`
	MaxConcurrent   int        `gorm:"default:10" json:"max_concurrent"`
	RunningTasks    int        `gorm:"default:0" json:"running_tasks"`
	QueuedTasks     int        `gorm:"default:0" json:"queued_tasks"`
	CPUUsage        float64    `gorm:"default:0" json:"cpu_usage"`
	MemoryUsage     float64    `gorm:"default:0" json:"memory_usage"`
	LastHeartbeat   *time.Time `json:"last_heartbeat"`
	TasksCompleted  int64      `gorm:"default:0" json:"tasks_completed"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (Node) TableName() string { return "vs_nodes" }

const (
	NodeStatusOnline  = "online"
	NodeStatusOffline = "offline"
	NodeStatusDrain   = "drain"
)
