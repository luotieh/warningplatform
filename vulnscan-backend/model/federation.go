package model

import "time"

// --- 中心主控表 ---

type FederationTenant struct {
	ID        string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name      string    `gorm:"type:varchar(200);not null" json:"name"`
	Code      string    `gorm:"type:varchar(100);uniqueIndex;not null" json:"code"`
	Contact   string    `gorm:"type:varchar(200)" json:"contact"`
	Email     string    `gorm:"type:varchar(200)" json:"email"`
	Phone     string    `gorm:"type:varchar(50)" json:"phone"`
	Status    string    `gorm:"type:varchar(20);default:'active';index" json:"status"`
	Config    JSONMap   `gorm:"type:text" json:"config"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (FederationTenant) TableName() string { return "cm_tenant" }

const (
	TenantStatusActive    = "active"
	TenantStatusSuspended = "suspended"
	TenantStatusExpired   = "expired"
)

type SubMaster struct {
	ID            string `gorm:"primarykey;type:varchar(36)" json:"id"`
	TenantID      string `gorm:"type:varchar(36);index" json:"tenant_id"`
	SubMasterCode string `gorm:"type:varchar(100);uniqueIndex;not null" json:"sub_master_code"`
	Name          string `gorm:"type:varchar(200)" json:"name"`
	Hostname      string `gorm:"type:varchar(200)" json:"hostname"`
	IPAddress     string `gorm:"type:varchar(50)" json:"ip_address"`
	Version       string `gorm:"type:varchar(50)" json:"version"`
	Status        string `gorm:"type:varchar(20);default:'offline';index" json:"status"`

	PocVersion         int64      `gorm:"default:0" json:"poc_version"`
	FingerprintVersion int64      `gorm:"default:0" json:"fingerprint_version"`
	RuleVersion        int64      `gorm:"default:0" json:"rule_version"`
	LastSyncAt         *time.Time `json:"last_sync_at"`

	LastHeartbeatAt *time.Time `json:"last_heartbeat_at"`
	CPUPercent      float64    `gorm:"default:0" json:"cpu_percent"`
	MemPercent      float64    `gorm:"default:0" json:"mem_percent"`
	WorkerCount     int        `gorm:"default:0" json:"worker_count"`
	ActiveTasks     int        `gorm:"default:0" json:"active_tasks"`

	CurrentTargets int `gorm:"default:0" json:"current_targets"`
	ScansToday     int `gorm:"default:0" json:"scans_today"`

	LicenseID        string     `gorm:"type:varchar(36)" json:"license_id"`
	LicenseExpiresAt *time.Time `json:"license_expires_at"`

	Capabilities StringArray `gorm:"type:text" json:"capabilities"`
	Labels       JSONMap     `gorm:"type:text" json:"labels"`

	APIToken  string    `gorm:"type:varchar(500)" json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (SubMaster) TableName() string { return "cm_sub_master" }

const (
	SubMasterOnline      = "online"
	SubMasterOffline     = "offline"
	SubMasterDegraded    = "degraded"
	SubMasterMaintenance = "maintenance"
)

type FederationLicense struct {
	ID          string `gorm:"primarykey;type:varchar(36)" json:"id"`
	TenantID    string `gorm:"type:varchar(36);index" json:"tenant_id"`
	SubMasterID string `gorm:"type:varchar(36)" json:"sub_master_id"`
	LicenseKey  string `gorm:"type:varchar(500);uniqueIndex;not null" json:"-"`

	MaxWorkers  int         `gorm:"default:5" json:"max_workers"`
	MaxTargets  int         `gorm:"default:1000" json:"max_targets"`
	MaxScansDay int         `gorm:"default:50" json:"max_scans_day"`
	Modules     StringArray `gorm:"type:text" json:"modules"`
	Features    StringArray `gorm:"type:text" json:"features"`

	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	GracePeriod int       `gorm:"default:30" json:"grace_period"`

	Status    string `gorm:"type:varchar(20);default:'active'" json:"status"`
	Signature string `gorm:"type:text" json:"-"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (FederationLicense) TableName() string { return "cm_license" }

const (
	LicenseActive  = "active"
	LicenseExpired = "expired"
	LicenseRevoked = "revoked"
)

type SyncVersion struct {
	DataType       string    `gorm:"primarykey;type:varchar(50)" json:"data_type"`
	CurrentVersion int64     `gorm:"default:0" json:"current_version"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (SyncVersion) TableName() string { return "cm_sync_version" }

const (
	SyncDataTypePoc         = "poc"
	SyncDataTypeFingerprint = "fingerprint"
	SyncDataTypeRule        = "rule"
)

type SyncLog struct {
	ID           string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	SubMasterID  string    `gorm:"type:varchar(100);index" json:"sub_master_id"`
	DataType     string    `gorm:"type:varchar(50);not null" json:"data_type"`
	FromVersion  int64     `json:"from_version"`
	ToVersion    int64     `json:"to_version"`
	RecordCount  int       `json:"record_count"`
	Status       string    `gorm:"type:varchar(20)" json:"status"`
	ErrorMessage string    `gorm:"type:text" json:"error_message"`
	DurationMs   int       `json:"duration_ms"`
	SyncedAt     time.Time `json:"synced_at"`
}

func (SyncLog) TableName() string { return "cm_sync_log" }

type AggregateVuln struct {
	ID          string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	SubMasterID string    `gorm:"type:varchar(100);not null" json:"sub_master_id"`
	TenantID    string    `gorm:"type:varchar(36);not null;index" json:"tenant_id"`
	ReportAt    time.Time `gorm:"not null;index" json:"report_at"`
	Period      string    `gorm:"type:varchar(20);not null" json:"period"`
	TotalVulns  int64     `gorm:"default:0" json:"total_vulns"`
	BySeverity  JSONMap   `gorm:"type:text" json:"by_severity"`
	ByType      JSONMap   `gorm:"type:text" json:"by_type"`
	NewVulns    int64     `gorm:"default:0" json:"new_vulns"`
	FixedVulns  int64     `gorm:"default:0" json:"fixed_vulns"`
	CreatedAt   time.Time `json:"created_at"`
}

func (AggregateVuln) TableName() string { return "cm_aggregate_vuln" }

type AggregateScan struct {
	ID             string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	SubMasterID    string    `gorm:"type:varchar(100);not null" json:"sub_master_id"`
	TenantID       string    `gorm:"type:varchar(36);not null;index" json:"tenant_id"`
	ReportAt       time.Time `gorm:"not null;index" json:"report_at"`
	ActiveTasks    int64     `gorm:"default:0" json:"active_tasks"`
	CompletedToday int64     `gorm:"default:0" json:"completed_today"`
	TotalTargets   int64     `gorm:"default:0" json:"total_targets"`
	ActiveWorkers  int64     `gorm:"default:0" json:"active_workers"`
	AvgScanTime    float64   `gorm:"default:0" json:"avg_scan_time"`
	CreatedAt      time.Time `json:"created_at"`
}

func (AggregateScan) TableName() string { return "cm_aggregate_scan" }

// --- 分主控本地表 ---

type FederationSyncState struct {
	DataType     string     `gorm:"primarykey;type:varchar(50)" json:"data_type"`
	LocalVersion int64      `gorm:"default:0" json:"local_version"`
	LastSyncAt   *time.Time `json:"last_sync_at"`
	LastError    string     `gorm:"type:text" json:"last_error"`
	RetryCount   int        `gorm:"default:0" json:"retry_count"`
}

func (FederationSyncState) TableName() string { return "federation_sync_state" }

type FederationReportBuffer struct {
	ID         string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	ReportType string    `gorm:"type:varchar(50);not null;index" json:"report_type"`
	Payload    JSONMap   `gorm:"type:text;not null" json:"payload"`
	Status     string    `gorm:"type:varchar(20);default:'pending';index" json:"status"`
	RetryCount int       `gorm:"default:0" json:"retry_count"`
	CreatedAt  time.Time `json:"created_at"`
}

func (FederationReportBuffer) TableName() string { return "federation_report_buffer" }
