package agent

import "time"

const Version = "2.0.0"

type Config struct {
	MasterURL         string
	Token             string
	Secret            string
	MaxConcurrent     int
	TaskTimeout       time.Duration
	HeartbeatInterval time.Duration
}

func (c *Config) defaults() {
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 10
	}
	if c.TaskTimeout <= 0 {
		c.TaskTimeout = 10 * time.Minute
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = 10 * time.Second
	}
}
