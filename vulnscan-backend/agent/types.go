package agent

import "encoding/json"

type TaskEnvelope struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Priority int             `json:"priority"`
	Payload  json.RawMessage `json:"payload"`
}

type TaskResult struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	AgentID    string `json:"agent_id"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	Result     string `json:"result,omitempty"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

type HeartbeatReq struct {
	RunningTasks  int     `json:"running_tasks"`
	QueuedTasks   int     `json:"queued_tasks"`
	MaxConcurrent int     `json:"max_concurrent"`
	CPUUsage      float64 `json:"cpu_usage"`
	MemoryUsage   float64 `json:"memory_usage"`
	Version       string  `json:"version"`
	IPAddress     string  `json:"ip_address"`
	MacAddress    string  `json:"mac_address"`
}
