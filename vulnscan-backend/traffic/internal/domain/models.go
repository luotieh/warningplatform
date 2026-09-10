package domain

import (
	"strings"
	"time"
)

type APIResponse struct {
	Status  string      `json:"status,omitempty"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type User struct {
	ID          int64      `json:"id"`
	UserID      string     `json:"user_id"`
	Username    string     `json:"username"`
	Nickname    string     `json:"nickname,omitempty"`
	Email       string     `json:"email,omitempty"`
	Phone       string     `json:"phone,omitempty"`
	Password    string     `json:"-"`
	Role        string     `json:"role"`
	IsActive    bool       `json:"is_active"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Event struct {
	ID            int64      `json:"id"`
	EventID       string     `json:"event_id"`
	EventName     string     `json:"event_name,omitempty"`
	Title         string     `json:"title,omitempty"`
	Message       string     `json:"message"`
	Context       string     `json:"context,omitempty"`
	Source        string     `json:"source,omitempty"`
	Severity      string     `json:"severity"`
	Category      string     `json:"category,omitempty"`
	EventStatus   string     `json:"event_status"`
	CurrentRound  int        `json:"current_round"`
	Observables   []IOC      `json:"observables,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ReviewStatus  string     `json:"review_status"`
	ReviewComment string     `json:"review_comment,omitempty"`
	ReviewedBy    string     `json:"reviewed_by,omitempty"`
	ReviewedAt    *time.Time `json:"reviewed_at,omitempty"`
	CircularCode  string     `json:"circular_code,omitempty"`
	// AnalysisVersion 分析版本：0=未分析，1=初版快报，2=收敛终报，>=3=手动刷新。
	AnalysisVersion int `json:"analysis_version"`
	// AggregationClosed 聚合是否已收敛（quant_stats 冻结）。
	AggregationClosed bool `json:"aggregation_closed"`
	// LastAnalysisAt 最近一次分析完成时间，用于手动刷新冷却。
	LastAnalysisAt *time.Time `json:"last_analysis_at,omitempty"`
	// LastSeenAt 服务器最近一次收到该聚合命中的时刻（收敛判定专用列）。
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	// ArchiveDate 逻辑归档日（Asia/Shanghai 自然日）；NULL=未归档（今日视图）。
	ArchiveDate *time.Time `json:"archive_date,omitempty"`
}

// ArchiveJob 每日归档任务记录（审计/进度查询）。
type ArchiveJob struct {
	ID        int64     `json:"id"`
	JobID     string    `json:"job_id"`
	Period    string    `json:"period"` // YYYY-MM-DD（Asia/Shanghai 归档目标日）
	Status    string    `json:"status"` // running/success/failed
	Total     int       `json:"total"`
	Processed int       `json:"processed"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type IOC struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Role  string `json:"role,omitempty"`
}

const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleCaptain   = "_captain"
	RoleManager   = "_manager"
	RoleOperator  = "_operator"
	RoleExecutor  = "_executor"
	RoleExpert    = "_expert"
)

var AgentRoles = []string{RoleCaptain, RoleManager, RoleOperator, RoleExecutor, RoleExpert}

func NormalizeMessageFrom(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "system":
		return RoleSystem
	case "user", "engineer", "human":
		return RoleUser
	case "assistant", "ai", "ai_assistant", "engineer_ai":
		return RoleAssistant
	case "captain", "role_soc_captain", "soc_captain", "_captain":
		return RoleCaptain
	case "manager", "role_soc_manager", "soc_manager", "_manager":
		return RoleManager
	case "operator", "role_soc_operator", "soc_operator", "_operator":
		return RoleOperator
	case "executor", "role_soc_executor", "soc_executor", "_executor", "autopilot", "queue-worker":
		return RoleExecutor
	case "expert", "role_soc_expert", "soc_expert", "_expert":
		return RoleExpert
	default:
		return strings.TrimSpace(v)
	}
}

func SenderType(messageFrom string) string {
	switch NormalizeMessageFrom(messageFrom) {
	case RoleUser:
		return "user"
	case RoleAssistant:
		return "ai"
	case RoleSystem:
		return "system"
	default:
		return "agent"
	}
}

func NormalizeMessage(m Message) Message {
	m.MessageFrom = NormalizeMessageFrom(m.MessageFrom)
	if m.SenderType == "" || m.SenderType == "unknown" {
		m.SenderType = SenderType(m.MessageFrom)
	}
	if m.MessageCategory == "" {
		if m.SenderType == "user" || m.SenderType == "ai" {
			m.MessageCategory = "engineer_chat"
		} else {
			m.MessageCategory = "agent"
		}
	}
	return m
}

func IsInternalMessage(m Message) bool {
	t := strings.ToLower(strings.TrimSpace(m.MessageType))
	return t == "llm_request" || strings.HasSuffix(t, "_llm_request")
}

type Message struct {
	ID              int64     `json:"id"`
	MessageID       string    `json:"message_id"`
	EventID         string    `json:"event_id"`
	UserID          string    `json:"user_id,omitempty"`
	UserNickname    string    `json:"user_nickname,omitempty"`
	MessageFrom     string    `json:"message_from"`
	MessageType     string    `json:"message_type"`
	MessageContent  string    `json:"message_content"`
	RoundID         int       `json:"round_id"`
	MessageCategory string    `json:"message_category,omitempty"`
	SenderType      string    `json:"sender_type,omitempty"`
	ChatSessionID   string    `json:"chat_session_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type Task struct {
	ID              int64     `json:"id"`
	TaskID          string    `json:"task_id"`
	EventID         string    `json:"event_id"`
	TaskName        string    `json:"task_name"`
	TaskType        string    `json:"task_type,omitempty"`
	TaskDescription string    `json:"task_description,omitempty"`
	TaskStatus      string    `json:"task_status"`
	TaskPriority    string    `json:"task_priority,omitempty"`
	AssignedTo      string    `json:"assigned_to,omitempty"`
	TaskAssignee    string    `json:"task_assignee,omitempty"`
	RoundID         int       `json:"round_id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Action struct {
	ID             int64     `json:"id"`
	ActionID       string    `json:"action_id"`
	TaskID         string    `json:"task_id"`
	EventID        string    `json:"event_id"`
	RoundID        int       `json:"round_id"`
	ActionName     string    `json:"action_name"`
	ActionType     string    `json:"action_type,omitempty"`
	ActionAssignee string    `json:"action_assignee,omitempty"`
	ActionStatus   string    `json:"action_status"`
	ActionResult   string    `json:"action_result,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Command struct {
	ID              int64     `json:"id"`
	CommandID       string    `json:"command_id"`
	ActionID        string    `json:"action_id"`
	TaskID          string    `json:"task_id"`
	EventID         string    `json:"event_id"`
	RoundID         int       `json:"round_id"`
	CommandName     string    `json:"command_name"`
	CommandType     string    `json:"command_type,omitempty"`
	CommandAssignee string    `json:"command_assignee,omitempty"`
	CommandEntity   string    `json:"command_entity,omitempty"`
	CommandParams   string    `json:"command_params,omitempty"`
	CommandStatus   string    `json:"command_status"`
	CommandResult   string    `json:"command_result,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Execution struct {
	ID               int64     `json:"id"`
	ExecutionID      string    `json:"execution_id"`
	EventID          string    `json:"event_id"`
	TaskID           string    `json:"task_id,omitempty"`
	ActionID         string    `json:"action_id,omitempty"`
	RoundID          int       `json:"round_id,omitempty"`
	CommandID        string    `json:"command_id,omitempty"`
	ExecutionStatus  string    `json:"execution_status"`
	ExecutionResult  string    `json:"execution_result,omitempty"`
	ExecutionSummary string    `json:"execution_summary,omitempty"`
	AISummary        string    `json:"ai_summary,omitempty"`
	CommandName      string    `json:"command_name,omitempty"`
	CommandType      string    `json:"command_type,omitempty"`
	CommandEntity    string    `json:"command_entity,omitempty"`
	CommandParams    string    `json:"command_params,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type Summary struct {
	ID           int64  `json:"id"`
	EventID      string `json:"event_id"`
	RoundID      int    `json:"round_id"`
	EventSummary string `json:"event_summary"`
	// Version 分析版本（与 Event.AnalysisVersion 对应）。
	Version int `json:"version"`
	// Kind 分析类型：initial / final / manual。
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type LyEvent map[string]any

type EventMap struct {
	Fingerprint    string    `json:"fingerprint"`
	LyEventID      string    `json:"ly_event_id,omitempty"`
	DeepSOCEventID string    `json:"deepsoc_event_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type SyncCursor struct {
	Name      string    `json:"name"`
	LastTS    string    `json:"last_ts"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PushedEvent struct {
	LyEventID      string    `json:"ly_event_id"`
	IdempotencyKey string    `json:"idempotency_key"`
	DeepSOCEventID string    `json:"deepsoc_event_id"`
	Status         string    `json:"status"`
	Attempts       int       `json:"attempts"`
	LastError      string    `json:"last_error"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type AuditLog struct {
	ID        int64     `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Meta      string    `json:"meta,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Asset struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AssetType string    `json:"asset_type"`
	Address   string    `json:"address"`
	Unit      string    `json:"unit,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	Status    int       `json:"status"`
	Remark    string    `json:"remark,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// QuantStats 事件聚合量化统计，随命中合并增量维护、收敛时冻结。
type QuantStats struct {
	EventID         string           `json:"event_id"`
	WindowStart     string           `json:"window_start"`
	WindowEnd       string           `json:"window_end"`
	DurationSec     int64            `json:"duration_sec"`
	OccurrenceCount int64            `json:"occurrence_count"`
	UniqueSrcIPs    int              `json:"unique_src_ips"`
	UniqueDstIPs    int              `json:"unique_dst_ips"`
	SourceIPs       map[string]int64 `json:"source_ips,omitempty"`
	DestIPs         map[string]int64 `json:"dest_ips,omitempty"`
	TotalWireBytes  int64            `json:"total_wire_bytes"`
	// TotalPayloadBytes 载荷总字节（ta_node bytes 字段累加），列表「总载荷」排序口径。
	TotalPayloadBytes int64          `json:"total_payload_bytes"`
	TotalPackets    int64            `json:"total_packets"`
	RatePerMin      float64          `json:"rate_per_min"`
	ByRule          map[string]int64 `json:"by_rule"`
	ByDirection     map[string]int64 `json:"by_direction"`
	ByIOC           []IocHitStat     `json:"by_ioc"`
	PeakWindow      PeakWindowStat   `json:"peak_window"`
	UpdatedAt       string           `json:"updated_at"`
}

type IocHitStat struct {
	IOCValue  string `json:"ioc_value"`
	IOCType   string `json:"ioc_type"`
	Count     int64  `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

type PeakWindowStat struct {
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Count     int64  `json:"count"`
}

// AssetReportSummary 资产 IP 月度总结（目标 IP 一个月内落档报告的汇总分析）。
type AssetReportSummary struct {
	ID         string            `json:"id"`
	AssetID    string            `json:"asset_id"`
	AssetIP    string            `json:"asset_ip"`
	Period     string            `json:"period"` // 2026-08
	WindowFrom string            `json:"window_from"`
	WindowTo   string            `json:"window_to"`
	EventCount int               `json:"event_count"`
	Stats      AssetMonthlyStats `json:"stats"`
	Narrative  string            `json:"narrative"` // LLM 月度总结
	Status     string            `json:"status"`    // pending/completed/failed
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

type AssetMonthlyStats struct {
	ClosedCount      int            `json:"closed_count"`
	BySeverity       map[string]int `json:"by_severity"`
	ByEventType      map[string]int `json:"by_event_type"`
	ByStatus         map[string]int `json:"by_status"`
	TotalOccurrences int64          `json:"total_occurrences"`
	TotalWireBytes   int64          `json:"total_wire_bytes"`
	TopSources       []CountItem    `json:"top_sources"`
	TopIOCs          []CountItem    `json:"top_iocs"`
	TopRules         []CountItem    `json:"top_rules"`
	FirstEventTime   string         `json:"first_event_time"`
	LastEventTime    string         `json:"last_event_time"`
}

type CountItem struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// AssetReportJob 资产月度总结异步任务。
type AssetReportJob struct {
	ID              string     `json:"id"`
	Period          string     `json:"period"`
	Status          string     `json:"status"` // queued/running/completed/failed
	TotalAssets     int        `json:"total_assets"`
	CompletedAssets int        `json:"completed_assets"`
	Error           string     `json:"error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
}
