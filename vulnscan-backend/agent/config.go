package agent

import "time"

const Version = "2.0.0"

type Config struct {
	MasterURL         string
	Token             string
	Secret            string
	Topology          string // master_public_node_private | master_private_node_public
	MaxConcurrent     int
	TaskTimeout       time.Duration
	HeartbeatInterval time.Duration
}

func (c *Config) defaults() {
	// MaxConcurrent <= 0 表示由 nodecapacity 按本机资源自动计算（预留 10% 系统余量）
	if c.TaskTimeout <= 0 {
		c.TaskTimeout = 10 * time.Minute
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = 10 * time.Second
	}
}
