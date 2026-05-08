package ws

import (
	"encoding/json"
	"time"
)

// Message types exchanged over WebSocket.
const (
	MsgTypeRegister      = "register"
	MsgTypeRegisterAck   = "register_ack"
	MsgTypeHeartbeat     = "heartbeat"
	MsgTypeHeartbeatAck  = "heartbeat_ack"
	MsgTypePollTask      = "poll_task"
	MsgTypeTaskAssign    = "task_assign"
	MsgTypeTaskProgress  = "task_progress"
	MsgTypeTaskResult    = "task_result"
	MsgTypeTaskResultAck = "task_result_ack"
	MsgTypeBanReport     = "ban_report"
	MsgTypeCommand       = "command"
	MsgTypePing          = "ping"
	MsgTypePong          = "pong"
)

// Envelope is the top-level JSON message wrapper.
type Envelope struct {
	Type      string          `json:"type"`
	Timestamp int64           `json:"ts"`
	Data      json.RawMessage `json:"data,omitempty"`
}

func NewEnvelope(msgType string, data interface{}) (*Envelope, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Type:      msgType,
		Timestamp: time.Now().UnixMilli(),
		Data:      raw,
	}, nil
}

// --- Data payloads ---

type RegisterPayload struct {
	WorkerID string `json:"worker_id"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Capacity int    `json:"capacity"`
	Version  string `json:"version"`
}

type RegisterAckPayload struct {
	OK    bool   `json:"ok"`
	Token string `json:"token,omitempty"`
	Error string `json:"error,omitempty"`
}

type HeartbeatPayload struct {
	WorkerID          string  `json:"worker_id"`
	ActiveTasks       int     `json:"active_tasks"`
	Capacity          int     `json:"capacity"`
	CPUUsage          float64 `json:"cpu_usage"`
	MemUsage          float64 `json:"mem_usage"`
	BandwidthMbps     float64 `json:"bandwidth_mbps"`
	AvgLatencyMs      float64 `json:"avg_latency_ms"`
	ProxyHealthyCount int     `json:"proxy_healthy_count"`
	ProxyTotalCount   int     `json:"proxy_total_count"`
}

type HeartbeatAckPayload struct {
	OK       bool      `json:"ok"`
	Commands []Command `json:"commands,omitempty"`
}

type Command struct {
	Action string `json:"action"`
	TaskID string `json:"task_id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type PollTaskPayload struct {
	WorkerID string `json:"worker_id"`
	Slots    int    `json:"slots"`
}

type TaskAssignPayload struct {
	TaskID     string                 `json:"task_id"`
	Name       string                 `json:"name"`
	Targets    []string               `json:"targets"`
	Config     map[string]interface{} `json:"config"`
	Parameters map[string]interface{} `json:"parameters"`
	Priority   int                    `json:"priority"`
	Type       string                 `json:"type"`
}

type TaskProgressPayload struct {
	TaskID       string  `json:"task_id"`
	WorkerID     string  `json:"worker_id"`
	Progress     float64 `json:"progress"`
	CurrentStage string  `json:"current_stage"`
}

type TaskResultPayload struct {
	TaskID     string      `json:"task_id"`
	WorkerID   string      `json:"worker_id"`
	Status     string      `json:"status"`
	Progress   float64     `json:"progress"`
	Error      string      `json:"error,omitempty"`
	FinishedAt *time.Time  `json:"finished_at,omitempty"`
	Vulns      []VulnBrief `json:"vulns,omitempty"`
}

type VulnBrief struct {
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	ModuleID string `json:"module_id"`
	Evidence string `json:"evidence,omitempty"`
}

type BanReportPayload struct {
	WorkerID   string `json:"worker_id"`
	TaskID     string `json:"task_id"`
	TargetHost string `json:"target_host"`
	Reason     string `json:"reason"`
}
