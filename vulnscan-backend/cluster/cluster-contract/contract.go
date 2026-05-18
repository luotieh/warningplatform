package clusterContract

import (
	"context"
	"time"
	"vulnscan-backend/model"
	"vulnscan-backend/pkg/nodeenroll"
)

type HeartbeatPayload struct {
	WorkerID    string  `json:"worker_id" binding:"required"`
	ActiveTasks int     `json:"active_tasks"`
	Capacity    int     `json:"capacity"`
	CPUUsage    float64 `json:"cpu_usage"`
	MemUsage    float64 `json:"mem_usage"`
	Version     string  `json:"version"`

	BandwidthMbps     float64  `json:"bandwidth_mbps"`
	AvgLatencyMs      float64  `json:"avg_latency_ms"`
	ProxyHealthyCount int      `json:"proxy_healthy_count"`
	ProxyTotalCount   int      `json:"proxy_total_count"`
	BannedTargets     []string `json:"banned_targets,omitempty"`
}

// HeartbeatResponse is returned to the worker on each heartbeat.
// Workers MUST process embedded Commands immediately.
type HeartbeatResponse struct {
	OK       bool              `json:"ok"`
	Commands []WorkerCommand   `json:"commands,omitempty"`
	Config   map[string]string `json:"config,omitempty"`
}

type WorkerCommand struct {
	Action string `json:"action"`
	TaskID string `json:"task_id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

const (
	CmdCancelTask   = "cancel_task"
	CmdPauseTask    = "pause_task"
	CmdDrainWorker  = "drain"
	CmdResumeWorker = "resume"
	CmdUpdateConfig = "update_config"
)

type TaskAssignment struct {
	TaskID     string        `json:"task_id"`
	Targets    []string      `json:"targets"`
	Config     model.JSONMap `json:"config"`
	Priority   int           `json:"priority"`
	AssignedAt time.Time     `json:"assigned_at"`
}

type TaskResult struct {
	TaskID          string                `json:"task_id"`
	WorkerID        string                `json:"worker_id"`
	Status          string                `json:"status"`
	Progress        float64               `json:"progress"`
	CurrentStage    string                `json:"current_stage,omitempty"`
	Vulnerabilities []model.Vulnerability `json:"vulnerabilities,omitempty"`
	Error           string                `json:"error,omitempty"`
	FinishedAt      *time.Time            `json:"finished_at,omitempty"`
}

type PollTaskRequest struct {
	WorkerID string `json:"worker_id" binding:"required"`
	Slots    int    `json:"slots"`
}

type BanReport struct {
	WorkerID   string `json:"worker_id" binding:"required"`
	TaskID     string `json:"task_id" binding:"required"`
	TargetHost string `json:"target_host" binding:"required"`
	Reason     string `json:"reason"`
}

// KnowledgeManifestDTO 主控侧 PoC/指纹/扫描规则同步游标（供扫描节点对比）。
type KnowledgeManifestDTO struct {
	Versions   map[string]int64 `json:"versions"`
	ServerTime time.Time        `json:"server_time"`
}

// NodeEnrollmentIssueRequest wraps enrollment.json from the node plus optional master hints.
type NodeEnrollmentIssueRequest struct {
	Enrollment nodeenroll.EnrollmentFile `json:"enrollment"`
	MasterURL  string                    `json:"master_url"`
	Label      string                    `json:"label"`
}

// NodeAgentCredentialsFile is returned to the operator once; the agent loads it via AGENT_CREDENTIALS_FILE.
type NodeAgentCredentialsFile struct {
	Version   int    `json:"version"`
	MasterURL string `json:"master_url"`
	NodeUUID  string `json:"node_uuid"`
	Secret    string `json:"secret"`
	IssuedAt  string `json:"issued_at"`
	Label     string `json:"label,omitempty"`
}

const NodeAgentCredentialsVersion = 1

// NodeEnrollmentIssueResponse is returned by POST /cluster/scan-nodes/enroll.
// When enrollment includes public_key_pem, Encrypted is true and only Envelope is set (no plaintext secret on the wire).
type NodeEnrollmentIssueResponse struct {
	Encrypted   bool                           `json:"encrypted"`
	Credentials *NodeAgentCredentialsFile      `json:"credentials,omitempty"`
	Envelope    *nodeenroll.CredentialEnvelope `json:"envelope,omitempty"`
}

type WorkerQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Status   string `form:"status"`
}

type ServiceCluster interface {
	RegisterWorker(ctx context.Context, node *model.WorkerNode) error
	Heartbeat(ctx context.Context, payload *HeartbeatPayload) (*HeartbeatResponse, error)
	UnregisterWorker(ctx context.Context, workerID string) error
	ListWorkers(query WorkerQuery) ([]model.WorkerNode, int64, error)
	GetWorker(id string) (*model.WorkerNode, error)

	PollTask(ctx context.Context, workerID string, slots int) ([]*model.ScanTask, error)
	ReportTaskResult(ctx context.Context, result *TaskResult) error
	ReportBan(ctx context.Context, report *BanReport) error

	CheckStaleWorkers(ctx context.Context, timeout time.Duration) ([]model.WorkerNode, error)

	KnowledgeManifest(ctx context.Context) (*KnowledgeManifestDTO, error)

	// IssueScanNodeCredentials validates enrollment.json, creates vs_nodes row, returns plaintext or RSA-wrapped credentials.
	IssueScanNodeCredentials(ctx context.Context, req *NodeEnrollmentIssueRequest) (*NodeEnrollmentIssueResponse, error)
}
