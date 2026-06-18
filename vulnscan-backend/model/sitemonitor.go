package model

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"time"
)

// ═══ 监测目标与路径任务 ═══

const (
	MonitorTargetTypeDomain = "domain"
	MonitorTargetTypeIP     = "ip"
)

// MonitorTarget 监测目标（域名或 IP，可带虚拟主机）。
type MonitorTarget struct {
	BaseModel
	Name                 string     `json:"name" gorm:"type:varchar(200);not null"`
	TargetType           string     `json:"target_type" gorm:"type:varchar(20);not null;index"`
	TargetValue          string     `json:"target_value" gorm:"type:varchar(500);not null"`
	DefaultScheme        string     `json:"default_scheme" gorm:"type:varchar(10);default:https"`
	VirtualHost          string     `json:"virtual_host" gorm:"type:varchar(500)"`
	ExpectedIPs          string     `json:"expected_ips" gorm:"type:text"`
	AssetID              string     `json:"asset_id" gorm:"type:varchar(36);index"`
	Enabled              bool       `json:"enabled" gorm:"not null;default:true"`
	Notes                string     `json:"notes" gorm:"type:varchar(500)"`
	ScheduleEnabled      bool       `json:"schedule_enabled" gorm:"default:false"`
	ScheduleCron         string     `json:"schedule_cron" gorm:"type:varchar(100)"`
	ScheduleJitter       int        `json:"schedule_jitter" gorm:"default:0"`
	NextRunAt            *time.Time `json:"next_run_at" gorm:"index"`
	ConfigDomainHijack   JSONMap    `json:"config_domain_hijack" gorm:"type:text"`
	ConfigSensitiveFile  JSONMap    `json:"config_sensitive_file" gorm:"type:text"`
	LastRunDomainHijack  *time.Time `json:"last_run_domain_hijack"`
	LastRunSensitiveFile *time.Time `json:"last_run_sensitive_file"`
}

func (MonitorTarget) TableName() string { return "monitor_targets" }

func (m *MonitorTarget) GetDimensionConfig(dim string) JSONMap {
	switch dim {
	case "domain_hijack":
		return m.ConfigDomainHijack
	case "sensitive_file":
		return m.ConfigSensitiveFile
	}
	return nil
}

func (m *MonitorTarget) SetDimensionConfig(dim string, cfg JSONMap) {
	switch dim {
	case "domain_hijack":
		m.ConfigDomainHijack = cfg
	case "sensitive_file":
		m.ConfigSensitiveFile = cfg
	}
}

func (m *MonitorTarget) GetLastRun(dim string) *time.Time {
	switch dim {
	case "domain_hijack":
		return m.LastRunDomainHijack
	case "sensitive_file":
		return m.LastRunSensitiveFile
	}
	return nil
}

// MonitorPathTask 路径级监测任务（挂在 MonitorTarget 下）。
type MonitorPathTask struct {
	BaseModel
	TargetID             string     `json:"target_id" gorm:"type:varchar(36);not null;index"`
	Name                 string     `json:"name" gorm:"type:varchar(200);not null"`
	Path                 string     `json:"path" gorm:"type:varchar(500);default:'/'"`
	URLOverride          string     `json:"url_override" gorm:"type:varchar(1000)"`
	AssetID              string     `json:"asset_id" gorm:"type:varchar(36);index"`
	Enabled              bool       `json:"enabled" gorm:"not null;default:true"`
	Notes                string     `json:"notes" gorm:"type:varchar(500)"`
	ScheduleEnabled      bool       `json:"schedule_enabled" gorm:"default:false"`
	ScheduleCron         string     `json:"schedule_cron" gorm:"type:varchar(100)"`
	ScheduleJitter       int        `json:"schedule_jitter" gorm:"default:0"`
	NextRunAt            *time.Time `json:"next_run_at" gorm:"index"`
	ConfigAvailability   JSONMap    `json:"config_availability" gorm:"type:text"`
	ConfigTamper         JSONMap    `json:"config_tamper" gorm:"type:text"`
	ConfigSensitiveWord  JSONMap    `json:"config_sensitive_word" gorm:"type:text"`
	ConfigBlacklink      JSONMap    `json:"config_blacklink" gorm:"type:text"`
	LastRunAvailability  *time.Time `json:"last_run_availability"`
	LastRunTamper        *time.Time `json:"last_run_tamper"`
	LastRunSensitiveWord *time.Time `json:"last_run_sensitive_word"`
	LastRunBlacklink     *time.Time `json:"last_run_blacklink"`
}

func (MonitorPathTask) TableName() string { return "monitor_path_tasks" }

func (m *MonitorPathTask) GetDimensionConfig(dim string) JSONMap {
	switch dim {
	case "availability":
		return m.ConfigAvailability
	case "tamper":
		return m.ConfigTamper
	case "sensitive_word":
		return m.ConfigSensitiveWord
	case "blacklink":
		return m.ConfigBlacklink
	}
	return nil
}

func (m *MonitorPathTask) SetDimensionConfig(dim string, cfg JSONMap) {
	switch dim {
	case "availability":
		m.ConfigAvailability = cfg
	case "tamper":
		m.ConfigTamper = cfg
	case "sensitive_word":
		m.ConfigSensitiveWord = cfg
	case "blacklink":
		m.ConfigBlacklink = cfg
	}
}

func (m *MonitorPathTask) GetLastRun(dim string) *time.Time {
	switch dim {
	case "availability":
		return m.LastRunAvailability
	case "tamper":
		return m.LastRunTamper
	case "sensitive_word":
		return m.LastRunSensitiveWord
	case "blacklink":
		return m.LastRunBlacklink
	}
	return nil
}

func MonitorPathLastRunColumn(dim string) string {
	switch dim {
	case "availability":
		return "last_run_availability"
	case "tamper":
		return "last_run_tamper"
	case "sensitive_word":
		return "last_run_sensitive_word"
	case "blacklink":
		return "last_run_blacklink"
	}
	return ""
}

func MonitorTargetLastRunColumn(dim string) string {
	switch dim {
	case "domain_hijack":
		return "last_run_domain_hijack"
	case "sensitive_file":
		return "last_run_sensitive_file"
	}
	return ""
}

var MonitorPathDimensions = []string{
	"availability", "tamper", "sensitive_word", "blacklink",
}

var MonitorTargetDimensions = []string{
	"domain_hijack", "sensitive_file",
}

var MonitorAllDimensions = []string{
	"availability", "domain_hijack", "tamper",
	"sensitive_file", "sensitive_word", "blacklink",
}

// MonitorCrawlJob 目标站点爬虫任务。
type MonitorCrawlJob struct {
	ID          string     `gorm:"primarykey;type:varchar(36)" json:"id"`
	TargetID    string     `json:"target_id" gorm:"type:varchar(36);not null;index"`
	Status      string     `json:"status" gorm:"type:varchar(20);default:pending;index"`
	UseHeadless bool       `json:"use_headless" gorm:"default:true"`
	MaxDepth    int        `json:"max_depth" gorm:"default:2"`
	MaxPages    int        `json:"max_pages" gorm:"default:50"`
	SameHost    bool       `json:"same_host" gorm:"default:true"`
	Error       string     `json:"error" gorm:"type:text"`
	ResultJSON  string     `json:"result_json" gorm:"type:longtext"`
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (MonitorCrawlJob) TableName() string { return "monitor_crawl_jobs" }

const (
	MonitorCrawlStatusPending = "pending"
	MonitorCrawlStatusRunning = "running"
	MonitorCrawlStatusSuccess = "success"
	MonitorCrawlStatusFailed  = "failed"
)

type MonitorDefaultConfig struct {
	ID         string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	Dimension  string    `json:"dimension" gorm:"type:varchar(50);not null;uniqueIndex"`
	ConfigJSON JSONMap   `json:"config_json" gorm:"type:text"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (MonitorDefaultConfig) TableName() string { return "monitor_default_configs" }

var MonitorDefaultConfigSeeds = map[string]map[string]any{
	"availability": {
		"enabled": true, "alert_enabled": true, "cycle_minutes": 5, "timeout_seconds": 60,
		"incident_auto_enabled": false, "incident_on_unavailable": true, "incident_max_response_time_ms": 0,
	},
	"domain_hijack": {
		"enabled": true, "alert_enabled": true, "cycle_minutes": 5,
		"incident_auto_enabled": false, "incident_on_hijack": true,
	},
	"tamper": {
		"enabled": true, "alert_enabled": true, "cycle_minutes": 5, "search_engine_ua": true,
		"incident_auto_enabled": false, "incident_min_diff_count": 1,
	},
	"sensitive_file": {
		"enabled": true, "alert_enabled": true, "cycle_type": "daily", "cycle_time": "02:00",
		"incident_auto_enabled": false, "incident_min_file_count": 1,
	},
	"sensitive_word": {
		"enabled": true, "alert_enabled": true, "cycle_minutes": 1,
		"incident_auto_enabled": false, "incident_min_match_count": 1,
	},
	"blacklink": {
		"enabled": true, "alert_enabled": true, "cycle_minutes": 1,
		"incident_auto_enabled": false, "incident_min_blacklink_count": 1,
		"trusted_domains": []any{},
	},
	"screenshot": {
		"width": 1920, "height": 1080, "quality": 80,
	},
}

// ═══ 执行记录 ═══

const (
	MonitorDispositionPending       = "pending"
	MonitorDispositionValid         = "valid"
	MonitorDispositionInvalid       = "invalid"
	MonitorDispositionFalsePositive = "false_positive"
)

type MonitorExecution struct {
	ID                string     `gorm:"primarykey;type:varchar(36)" json:"id"`
	TargetID          string     `json:"target_id" gorm:"type:varchar(36);index:idx_exec_target_dim_status;index;index:idx_exec_target_dim_created"`
	PathTaskID        string     `json:"path_task_id" gorm:"type:varchar(36);index:idx_exec_path_dim_status;index"`
	AgentID           string     `json:"agent_id" gorm:"type:varchar(80);index:idx_exec_status_agent;index"`
	Dimension         string     `json:"dimension" gorm:"type:varchar(50);not null;index:idx_exec_target_dim_status;index:idx_exec_path_dim_status;index:idx_exec_dim_status_created;index;index:idx_exec_target_dim_created"`
	URL               string     `json:"url" gorm:"type:varchar(500)"`
	Status            string     `json:"status" gorm:"type:varchar(20);default:pending;index:idx_exec_target_dim_status;index:idx_exec_path_dim_status;index:idx_exec_dim_status_created;index:idx_exec_status_agent;index"`
	HasIssue          bool       `json:"has_issue" gorm:"default:false"`
	Disposition       string     `json:"disposition" gorm:"type:varchar(20);default:pending;index"`
	DisposedAt        *time.Time `json:"disposed_at"`
	DisposedBy        string     `json:"disposed_by" gorm:"type:varchar(100)"`
	DispositionRemark string     `json:"disposition_remark" gorm:"type:text"`
	Error             string     `json:"error" gorm:"type:text"`
	ResultJSON        string     `json:"result_json" gorm:"type:longtext"`
	StartedAt         *time.Time `json:"started_at"`
	FinishedAt        *time.Time `json:"finished_at"`
	ReapedAt          *time.Time `json:"reaped_at"`
	CreatedAt         time.Time  `json:"created_at" gorm:"index:idx_exec_dim_status_created;index:idx_exec_target_dim_created"`
	// 问题去重字段：同一 URL + 维度 + 任务的重复问题合并到一条记录
	IssueKey        string     `json:"issue_key" gorm:"type:varchar(64);index"`
	FirstSeenAt     *time.Time `json:"first_seen_at"`
	OccurrenceCount int        `json:"occurrence_count" gorm:"default:1"`
}

func (MonitorExecution) TableName() string { return "monitor_executions" }

// MakeIssueKey 计算问题去重键：同一 URL + 维度 + 任务标识的问题视为同一问题。
func MakeIssueKey(url, dimension, targetID, pathTaskID string) string {
	taskKey := pathTaskID
	if taskKey == "" {
		taskKey = targetID
	}
	return fmt.Sprintf("%x", md5.Sum([]byte(url+":"+dimension+":"+taskKey)))
}

// ═══ 告警 ═══

const (
	MonitorAlertPending    = "pending"
	MonitorAlertSent       = "sent"
	MonitorAlertSuppressed = "suppressed"
)

type MonitorAlert struct {
	BaseModel
	TaskID          string     `json:"task_id" gorm:"type:varchar(50);not null;index"`
	ExecutionID     string     `json:"execution_id" gorm:"type:varchar(50);not null;index"`
	Dimension       string     `json:"dimension" gorm:"type:varchar(50);not null;index"`
	AlertType       string     `json:"alert_type" gorm:"type:varchar(100);not null"`
	AlertKey        string     `json:"alert_key" gorm:"type:varchar(64);not null;uniqueIndex"`
	Status          string     `json:"status" gorm:"type:varchar(20);default:pending"`
	SentAt          *time.Time `json:"sent_at"`
	SuppressedUntil *time.Time `json:"suppressed_until"`
	SuppressCount   int        `json:"suppress_count" gorm:"default:0"`
	Title           string     `json:"title" gorm:"type:varchar(500)"`
	Content         string     `json:"content" gorm:"type:text"`
	URL             string     `json:"url" gorm:"type:varchar(500)"`
	Error           string     `json:"error" gorm:"type:text"`
}

func (MonitorAlert) TableName() string { return "monitor_alerts" }

type MonitorAlertConfig struct {
	BaseModel
	SilenceDurationMinutes int    `json:"silence_duration_minutes" gorm:"default:60"`
	MaxAlertsPerHour       int    `json:"max_alerts_per_hour" gorm:"default:100"`
	WebhookURL             string `json:"webhook_url" gorm:"type:varchar(500)"`
	WebhookSecret          string `json:"webhook_secret" gorm:"type:varchar(200)"`
	EmailEnabled           bool   `json:"email_enabled" gorm:"default:false"`
	EmailReceivers         string `json:"email_receivers" gorm:"type:text"`
	DingTalkEnabled        bool   `json:"dingtalk_enabled" gorm:"default:false"`
	DingTalkWebhook        string `json:"dingtalk_webhook" gorm:"type:varchar(500)"`
	DingTalkSecret         string `json:"dingtalk_secret" gorm:"type:varchar(200)"`
	WechatEnabled          bool   `json:"wechat_enabled" gorm:"default:false"`
	WechatWebhook          string `json:"wechat_webhook" gorm:"type:varchar(500)"`
	AlertEnabled           bool   `json:"alert_enabled" gorm:"default:true"`
	MaxTamperScreenshots   int    `json:"max_tamper_screenshots" gorm:"default:10"`
}

func (MonitorAlertConfig) TableName() string { return "monitor_alert_config" }

type MonitorDispositionLog struct {
	BaseModel
	ExecutionID    string `json:"execution_id" gorm:"type:varchar(50);not null;index"`
	TaskID         string `json:"task_id" gorm:"type:varchar(50);not null;index"`
	OldDisposition string `json:"old_disposition" gorm:"type:varchar(20)"`
	NewDisposition string `json:"new_disposition" gorm:"type:varchar(20);not null"`
	Remark         string `json:"remark" gorm:"type:text"`
	Operator       string `json:"operator" gorm:"type:varchar(100);not null"`
}

func (MonitorDispositionLog) TableName() string { return "monitor_disposition_logs" }

// ═══ Agent ═══

type MonitorAgent struct {
	BaseModel
	UUID           string     `json:"uuid" gorm:"type:varchar(80);uniqueIndex"`
	Version        string     `json:"version" gorm:"type:varchar(50)"`
	Status         string     `json:"status" gorm:"type:varchar(20);default:offline"`
	LastHeartbeat  *time.Time `json:"last_heartbeat"`
	MacAddress     string     `json:"mac_address" gorm:"type:varchar(20)"`
	IPAddress      string     `json:"ip_address" gorm:"type:varchar(45)"`
	Region         string     `json:"region" gorm:"type:varchar(50);index"`
	Label          string     `json:"label" gorm:"type:varchar(200)"`
	RunningTasks   int        `json:"running_tasks" gorm:"default:0"`
	QueuedTasks    int        `json:"queued_tasks" gorm:"default:0"`
	MaxConcurrent  int        `json:"max_concurrent" gorm:"default:0"`
	CPUUsage       float64    `json:"cpu_usage" gorm:"default:0"`
	MemoryUsage    float64    `json:"memory_usage" gorm:"default:0"`
	MaxQueue       int        `json:"max_queue" gorm:"default:0"`
	TasksCompleted int64      `json:"tasks_completed" gorm:"default:0"`
}

func (MonitorAgent) TableName() string { return "monitor_agents" }

// ═══ 基线 ═══

type MonitorBaseline struct {
	BaseModel
	URL                   string `json:"url" gorm:"type:varchar(500);not null"`
	URLHash               string `json:"url_hash" gorm:"type:varchar(64);not null;uniqueIndex:idx_baseline_url_ver"`
	Version               int    `json:"version" gorm:"not null;default:1;uniqueIndex:idx_baseline_url_ver"`
	IsActive              bool   `json:"is_active" gorm:"default:true;index:idx_baseline_active"`
	ExecutionID           string `json:"execution_id" gorm:"type:varchar(80);uniqueIndex"`
	ContentHash           string `json:"content_hash" gorm:"type:varchar(64)"`
	Simhash               int64  `json:"simhash" gorm:"default:0"`
	DomStructureHash      string `json:"dom_structure_hash" gorm:"type:varchar(64)"`
	VisualHash            string `json:"visual_hash" gorm:"type:varchar(64)"`
	Title                 string `json:"title" gorm:"type:varchar(500)"`
	StatusCode            int    `json:"status_code" gorm:"default:0"`
	VisibleTextLength     int    `json:"visible_text_length" gorm:"default:0"`
	BodyText              string `json:"body_text" gorm:"type:text"`
	ExemptSelectorsJSON   string `json:"exempt_selectors_json" gorm:"type:text"`
	ExternalResourcesJSON string `json:"external_resources_json" gorm:"type:text"`
	ObjKeyHTML            string `json:"obj_key_html" gorm:"type:varchar(200)"`
	ObjKeyText            string `json:"obj_key_text" gorm:"type:varchar(200)"`
	ObjKeyScreenshot      string `json:"obj_key_screenshot" gorm:"type:varchar(200)"`
	AgentID               string `json:"agent_id" gorm:"type:varchar(100)"`
	ConfirmedBy           string `json:"confirmed_by" gorm:"type:varchar(20);default:auto"`
	Confidence            string `json:"confidence" gorm:"type:varchar(20);default:low"`
	SuspicionScore        int    `json:"suspicion_score" gorm:"default:0"`
	SuspicionDetail       string `json:"suspicion_detail" gorm:"type:text"`
	ConsecutiveStableRuns int    `json:"consecutive_stable_runs" gorm:"default:0"`
	WaybackVerified       bool   `json:"wayback_verified" gorm:"default:false"`
	CrossValidated        bool   `json:"cross_validated" gorm:"default:false"`
}

const (
	BaselineConfidenceLow    = "low"
	BaselineConfidenceMedium = "medium"
	BaselineConfidenceHigh   = "high"
)

func (MonitorBaseline) TableName() string { return "monitor_baselines" }

type MonitorFingerprintWindow struct {
	ID               int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	URLHash          string    `json:"url_hash" gorm:"type:varchar(64);not null;index"`
	Simhash          int64     `json:"simhash" gorm:"default:0"`
	DomStructureHash string    `json:"dom_structure_hash" gorm:"type:varchar(64)"`
	VisualHash       string    `json:"visual_hash" gorm:"type:varchar(64)"`
	ContentHash      string    `json:"content_hash" gorm:"type:varchar(64)"`
	IsNormal         bool      `json:"is_normal" gorm:"default:true"`
	CreatedAt        time.Time `json:"created_at"`
}

func (MonitorFingerprintWindow) TableName() string { return "monitor_fingerprint_windows" }

// ═══ 词库 ═══

type MonitorWordLibrary struct {
	BaseModel
	Name        string `json:"name" gorm:"type:varchar(200);not null"`
	Description string `json:"description" gorm:"type:varchar(500)"`
}

func (MonitorWordLibrary) TableName() string { return "monitor_word_libraries" }

type MonitorWordCategory struct {
	BaseModel
	LibraryID   string `json:"library_id" gorm:"type:varchar(80);not null;index"`
	Name        string `json:"name" gorm:"type:varchar(200);not null"`
	Description string `json:"description" gorm:"type:varchar(500)"`
}

func (MonitorWordCategory) TableName() string { return "monitor_word_categories" }

type MonitorWordEntry struct {
	ID         int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	CategoryID string    `json:"category_id" gorm:"type:varchar(80);not null;index"`
	Word       string    `json:"word" gorm:"type:varchar(500);not null"`
	Severity   string    `json:"severity" gorm:"type:varchar(20);default:medium"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (MonitorWordEntry) TableName() string { return "monitor_word_entries" }

// ═══ 文件库 ═══

type MonitorFileLibrary struct {
	BaseModel
	Name        string `json:"name" gorm:"type:varchar(200);not null"`
	Description string `json:"description" gorm:"type:varchar(500)"`
}

func (MonitorFileLibrary) TableName() string { return "monitor_file_libraries" }

type MonitorFileEntry struct {
	ID        int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	LibraryID string    `json:"library_id" gorm:"type:varchar(80);not null;index"`
	Path      string    `json:"path" gorm:"type:varchar(500);not null"`
	Mark      string    `json:"mark" gorm:"type:varchar(500)"`
	Risk      string    `json:"risk" gorm:"type:varchar(20);default:high"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (MonitorFileEntry) TableName() string { return "monitor_file_entries" }

// ═══ 检测结果 ═══

type MonitorResultSensitiveWord struct {
	ID                 int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	ExecutionID        string    `json:"execution_id" gorm:"type:varchar(80);not null;uniqueIndex"`
	TaskID             string    `json:"task_id" gorm:"type:varchar(80);not null;index"`
	URL                string    `json:"url" gorm:"type:varchar(500)"`
	HasHit             bool      `json:"has_hit" gorm:"default:false"`
	TotalMatches       int       `json:"total_matches" gorm:"default:0"`
	ScanTimeMs         int       `json:"scan_time_ms" gorm:"default:0"`
	SkippedIncremental bool      `json:"skipped_incremental" gorm:"default:false"`
	MatchSummaryJSON   string    `json:"match_summary_json" gorm:"type:text"`
	PreprocessingJSON  string    `json:"preprocessing_json" gorm:"type:text"`
	CreatedAt          time.Time `json:"created_at"`
}

func (MonitorResultSensitiveWord) TableName() string { return "monitor_result_sensitive_word" }

type MonitorResultSensitiveWordMatch struct {
	ID        int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	ResultID  int64     `json:"result_id" gorm:"not null;index"`
	Word      string    `json:"word" gorm:"type:varchar(500)"`
	Category  string    `json:"category" gorm:"type:varchar(100)"`
	Severity  string    `json:"severity" gorm:"type:varchar(20)"`
	Count     int       `json:"count" gorm:"default:1"`
	Context   string    `json:"context" gorm:"type:text"`
	Layer     string    `json:"layer" gorm:"type:varchar(20)"`
	CreatedAt time.Time `json:"created_at"`
}

func (MonitorResultSensitiveWordMatch) TableName() string {
	return "monitor_result_sensitive_word_matches"
}

type MonitorResultSensitiveFile struct {
	ID                   int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	ExecutionID          string    `json:"execution_id" gorm:"type:varchar(80);not null;uniqueIndex"`
	TaskID               string    `json:"task_id" gorm:"type:varchar(80);not null;index"`
	URL                  string    `json:"url" gorm:"type:varchar(500)"`
	HasHit               bool      `json:"has_hit" gorm:"default:false"`
	TotalChecked         int       `json:"total_checked" gorm:"default:0"`
	TotalFindings        int       `json:"total_findings" gorm:"default:0"`
	TotalProbeMs         int       `json:"total_probe_ms" gorm:"default:0"`
	CmsDetectedJSON      string    `json:"cms_detected_json" gorm:"type:text"`
	DirectoryListingJSON string    `json:"directory_listing_json" gorm:"type:text"`
	RiskSummaryJSON      string    `json:"risk_summary_json" gorm:"type:text"`
	CreatedAt            time.Time `json:"created_at"`
}

func (MonitorResultSensitiveFile) TableName() string { return "monitor_result_sensitive_file" }

type MonitorResultSensitiveFileFinding struct {
	ID            int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	ResultID      int64     `json:"result_id" gorm:"not null;index"`
	Path          string    `json:"path" gorm:"type:varchar(500)"`
	StatusCode    int       `json:"status_code" gorm:"default:0"`
	Mark          string    `json:"mark" gorm:"type:varchar(200)"`
	Risk          string    `json:"risk" gorm:"type:varchar(20)"`
	ContentType   string    `json:"content_type" gorm:"type:varchar(200)"`
	ContentLength int64     `json:"content_length" gorm:"default:0"`
	ProbeMs       int       `json:"probe_ms" gorm:"default:0"`
	Evidence      string    `json:"evidence" gorm:"type:text"`
	CreatedAt     time.Time `json:"created_at"`
}

func (MonitorResultSensitiveFileFinding) TableName() string {
	return "monitor_result_sensitive_file_findings"
}

// ═══ 规则数据 ═══

type MonitorRuleData struct {
	ModuleKey string    `json:"module_key" gorm:"type:varchar(50);primaryKey"`
	Data      string    `json:"data" gorm:"type:text;not null"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (MonitorRuleData) TableName() string { return "monitor_rule_data" }

func MonitorEncodeRuleData(rawJSON string) (string, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", fmt.Errorf("zlib writer: %w", err)
	}
	if _, err := w.Write([]byte(rawJSON)); err != nil {
		w.Close()
		return "", fmt.Errorf("zlib write: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("zlib close: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func MonitorDecodeRuleData(encoded string) (string, error) {
	if encoded == "" {
		return "{}", nil
	}
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return "", fmt.Errorf("zlib reader: %w", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("zlib decompress: %w", err)
	}
	return string(raw), nil
}

// ═══ NATS 消息类型 ═══

type MonitorAgentResult struct {
	AgentID     string `json:"agent_id"`
	ExecutionID string `json:"execution_id"`
	TaskID      string `json:"task_id"`
	Dimension   string `json:"dimension"`
	URL         string `json:"url"`
	Status      string `json:"status"`
	Result      string `json:"result"`
	Error       string `json:"error"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
}

type MonitorAgentStatus struct {
	UUID          string    `json:"uuid"`
	RunningTasks  int       `json:"running_tasks"`
	QueuedTasks   int       `json:"queued_tasks"`
	MaxConcurrent int       `json:"max_concurrent"`
	MaxQueue      int       `json:"max_queue"`
	CPUUsage      float64   `json:"cpu_usage"`
	MemoryUsage   float64   `json:"memory_usage"`
	Version       string    `json:"version"`
	MacAddress    string    `json:"mac_address"`
	IPAddress     string    `json:"ip_address"`
	Timestamp     time.Time `json:"timestamp"`
}

type MonitorTaskMessage struct {
	ExecutionID string                   `json:"execution_id"`
	TargetID    string                   `json:"target_id"`
	PathTaskID  string                   `json:"path_task_id,omitempty"`
	Dimension   string                   `json:"dimension"`
	URL         string                   `json:"url"`
	RequestHost string                   `json:"request_host,omitempty"`
	Config      map[string]any           `json:"config"`
	Baseline    *MonitorBaselineMetadata `json:"baseline,omitempty"`
}

type MonitorBaselineMetadata struct {
	Version           int            `json:"version"`
	Simhash           int64          `json:"simhash"`
	ContentHash       string         `json:"content_hash"`
	DomStructureHash  string         `json:"dom_structure_hash"`
	VisualHash        string         `json:"visual_hash"`
	Title             string         `json:"title"`
	StatusCode        int            `json:"status_code"`
	VisibleTextLength int            `json:"visible_text_length"`
	ExemptSelectors   []string       `json:"exempt_selectors"`
	ExternalResources map[string]any `json:"external_resources"`
	ObjKeyHTML        string         `json:"obj_key_html,omitempty"`
	ObjKeyText        string         `json:"obj_key_text,omitempty"`
	ObjKeyScreenshot  string         `json:"obj_key_screenshot,omitempty"`
	Confidence        string         `json:"confidence,omitempty"`
	SuspicionScore    int            `json:"suspicion_score,omitempty"`
}

type MonitorBaselineUpdate struct {
	Action            string         `json:"action"`
	Simhash           int64          `json:"simhash"`
	ContentHash       string         `json:"content_hash"`
	DomStructureHash  string         `json:"dom_structure_hash"`
	VisualHash        string         `json:"visual_hash"`
	Title             string         `json:"title"`
	StatusCode        int            `json:"status_code"`
	VisibleTextLength int            `json:"visible_text_length"`
	BodyText          string         `json:"body_text,omitempty"`
	ExemptSelectors   []string       `json:"exempt_selectors"`
	ExternalResources map[string]any `json:"external_resources"`
	ConfirmedBy       string         `json:"confirmed_by"`
	ObjKeyHTML        string         `json:"obj_key_html"`
	ObjKeyText        string         `json:"obj_key_text"`
	ObjKeyScreenshot  string         `json:"obj_key_screenshot"`
	SuspicionScore    int            `json:"suspicion_score,omitempty"`
	SuspicionDetail   string         `json:"suspicion_detail,omitempty"`
}

// ═══ NATS 检测结果类型（非 DB 模型） ═══

type MonitorTamperResult struct {
	URL            string                 `json:"url"`
	Tampered       bool                   `json:"tampered"`
	Severity       string                 `json:"severity"`
	Details        []string               `json:"details"`
	Fingerprints   map[string]any         `json:"fingerprints"`
	BaselineInfo   map[string]any         `json:"baseline_info"`
	Diff           map[string]any         `json:"diff"`
	HiddenTamper   []any                  `json:"hidden_tamper"`
	Evidence       map[string]any         `json:"evidence"`
	ScanTimeMs     float64                `json:"scan_time_ms"`
	BaselineUpdate *MonitorBaselineUpdate `json:"baseline_update,omitempty"`
}

type MonitorSensitiveWordResult struct {
	URL                string                            `json:"url"`
	HasHit             bool                              `json:"has_hit"`
	TotalMatches       int                               `json:"total_matches"`
	Matches            []MonitorSensitiveWordMatch       `json:"matches"`
	MatchSummary       map[string]MonitorCategorySummary `json:"match_summary"`
	MatchLayers        map[string]int                    `json:"match_layers"`
	ScanTimeMs         float64                           `json:"scan_time_ms"`
	SkippedIncremental bool                              `json:"skipped_incremental"`
	Preprocessing      MonitorSensitiveWordPreprocessing `json:"preprocessing"`
	Error              string                            `json:"error,omitempty"`
}

type MonitorSensitiveWordMatch struct {
	Word        string   `json:"word"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Count       int      `json:"count"`
	Contexts    []string `json:"contexts"`
	MatchLayers []string `json:"match_layers"`
}

type MonitorCategorySummary struct {
	Count int      `json:"count"`
	Words []string `json:"words"`
}

type MonitorSensitiveWordPreprocessing struct {
	TextLength   int     `json:"text_length"`
	StrippedLen  int     `json:"stripped_length"`
	Simhash      string  `json:"simhash"`
	PreprocessMs float64 `json:"preprocess_ms"`
	Note         string  `json:"note,omitempty"`
}

type MonitorSensitiveFileResult struct {
	URL              string                        `json:"url"`
	HasHit           bool                          `json:"has_hit"`
	CmsDetected      []string                      `json:"cms_detected"`
	Findings         []MonitorSensitiveFileFinding `json:"findings"`
	DirectoryListing bool                          `json:"directory_listing"`
	Stats            MonitorSensitiveFileStats     `json:"stats"`
	Error            string                        `json:"error,omitempty"`
}

type MonitorSensitiveFileFinding struct {
	URL           string  `json:"url"`
	Path          string  `json:"path"`
	Mark          string  `json:"mark"`
	Risk          string  `json:"risk"`
	StatusCode    int     `json:"status_code"`
	ContentLength int     `json:"content_length"`
	Detail        string  `json:"detail,omitempty"`
	ElapsedMs     float64 `json:"elapsed_ms"`
}

type MonitorSensitiveFileStats struct {
	TotalChecked  int            `json:"total_checked"`
	TotalFindings int            `json:"total_findings"`
	TotalProbeMs  int            `json:"total_probe_ms"`
	RiskSummary   map[string]int `json:"risk_summary"`
}

// ═══ 规则注册表 ═══

type MonitorModuleDef struct {
	Key         string
	Name        string
	Description string
	Type        string
	KVKey       string
	Group       string
	Icon        string
}

var MonitorModuleRegistry = map[string]MonitorModuleDef{
	"availability":  {Key: "availability", Name: "可用性检测规则", Description: "TLS 版本/加密套件、证书检查、HTTP 安全头、信息泄露头", Type: "engine", KVKey: "engine/availability", Group: "detect", Icon: "heartbeat"},
	"domain_hijack": {Key: "domain_hijack", Name: "域名劫持规则", Description: "劫持特征匹配、停靠/过期标题、Parking IP", Type: "engine", KVKey: "engine/domain_hijack", Group: "detect", Icon: "globe"},
	"tamper":        {Key: "tamper", Name: "篡改检测规则", Description: "噪音过滤模式、动态元素选择器、可信域名白名单", Type: "engine", KVKey: "engine/tamper", Group: "detect", Icon: "shield"},
	"blacklink":     {Key: "blacklink", Name: "暗链/后门检测", Description: "暗链 URL 规则、行业黑词、编码绕过模式、后门代码特征、后门路径字典", Type: "engine", KVKey: "engine/blacklink", Group: "detect", Icon: "link"},
	"malware":       {Key: "malware", Name: "恶意代码检测", Description: "恶意 JS 脚本、挖矿检测、恶意跳转、WebShell、恶意域名库", Type: "engine", KVKey: "engine/malware", Group: "detect", Icon: "bug"},
	"sf_engine":     {Key: "sf_engine", Name: "敏感文件引擎", Description: "敏感内容匹配、软 404 识别、备份文件后缀、高危目录、安全文件白名单", Type: "engine", KVKey: "engine/sensitive_file", Group: "detect", Icon: "file"},
	"sw_engine":     {Key: "sw_engine", Name: "敏感词引擎", Description: "违规链接检测规则", Type: "engine", KVKey: "engine/sensitive_word", Group: "detect", Icon: "search"},
	"common":        {Key: "common", Name: "公共配置", Description: "公共 DNS 服务器列表等共享配置", Type: "engine", KVKey: "engine/common", Group: "common", Icon: "settings"},
	"whiteip":       {Key: "whiteip", Name: "IP 白名单", Description: "可信 IP 地址，跳过检测", Type: "dict", KVKey: "data/whiteips", Group: "dict", Icon: "list"},
}

var MonitorValidSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true,
}

var MonitorRuleDataModuleKeys = []string{
	"availability", "domain_hijack", "tamper", "blacklink",
	"malware", "sf_engine", "sw_engine",
	"common", "whiteip",
}

type MonitorPerfBaseline struct {
	ID            string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	TaskID        string    `json:"task_id" gorm:"type:varchar(80);uniqueIndex"`
	AvgDNSMS      float64   `json:"avg_dns_ms" gorm:"default:0"`
	AvgTTFBMS     float64   `json:"avg_ttfb_ms" gorm:"default:0"`
	AvgTotalMS    float64   `json:"avg_total_ms" gorm:"default:0"`
	AvgContentLen int       `json:"avg_content_len" gorm:"default:0"`
	SampleCount   int       `json:"sample_count" gorm:"default:0"`
	P95TotalMS    float64   `json:"p95_total_ms" gorm:"default:0"`
	MaxTotalMS    float64   `json:"max_total_ms" gorm:"default:0"`
	MinTotalMS    float64   `json:"min_total_ms" gorm:"default:0"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (MonitorPerfBaseline) TableName() string { return "monitor_perf_baselines" }
