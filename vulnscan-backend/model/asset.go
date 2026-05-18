package model

import "time"

type DataSourceType = string

const (
	DataSourceManual    DataSourceType = "manual"
	DataSourceScan      DataSourceType = "scan"
	DataSourceImport    DataSourceType = "import"
	DataSourceDiscovery DataSourceType = "discovery"
)

type LifecycleState = string

const (
	LifecycleDiscovered   LifecycleState = "discovered"
	LifecycleConfirmed    LifecycleState = "confirmed"
	LifecycleRegistered   LifecycleState = "registered"
	LifecycleOperating    LifecycleState = "operating"
	LifecycleDecommission LifecycleState = "decommission"
	LifecycleOffline      LifecycleState = "offline"
)

type ReviewStatus = string

const (
	ReviewPending  ReviewStatus = "pending"
	ReviewApproved ReviewStatus = "approved"
	ReviewRejected ReviewStatus = "rejected"
)

type AlertStatus = string

const (
	AlertOpen     AlertStatus = "open"
	AlertAcked    AlertStatus = "acked"
	AlertResolved AlertStatus = "resolved"
)

type SeverityLevel = string

const (
	SeverityCritical SeverityLevel = "critical"
	SeverityHigh     SeverityLevel = "high"
	SeverityMedium   SeverityLevel = "medium"
	SeverityLow      SeverityLevel = "low"
	SeverityInfo     SeverityLevel = "info"
)

// Asset 资产主表（融合台账+技术探测双重视角）
type Asset struct {
	ID        string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	CreatedBy string    `gorm:"type:varchar(64)" json:"created_by"`
	UpdatedBy string    `gorm:"type:varchar(64)" json:"updated_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// ── 基础标识 ──
	Name    string `gorm:"type:varchar(200);not null" json:"name"`
	Type    string `gorm:"type:varchar(50);index" json:"type"`
	Address string `gorm:"type:varchar(500);not null;index" json:"address"`
	GroupID string `gorm:"type:varchar(36);index" json:"group_id"`
	Status  int    `gorm:"default:1;comment:1=活跃 0=不活跃" json:"status"`

	// ── 网络信息 ──
	Domain   string `gorm:"type:varchar(255)" json:"domain"`
	IPv4     string `gorm:"type:varchar(45);index" json:"ipv4"`
	IPv6     string `gorm:"type:varchar(50)" json:"ipv6"`
	URL      string `gorm:"type:varchar(500)" json:"url"`
	Port     int    `gorm:"default:0" json:"port"`
	Protocol string `gorm:"type:varchar(20)" json:"protocol"`
	Service  string `gorm:"type:varchar(100)" json:"service"`
	Version  string `gorm:"type:varchar(100)" json:"version"`
	OS       string `gorm:"type:varchar(100)" json:"os"`

	// ── 台账字段（从资产系统迁移）──
	DataNumber              string `gorm:"type:varchar(70);index" json:"data_number"`
	SystemType              string `gorm:"type:varchar(50)" json:"system_type"`
	AssetFamily             string `gorm:"type:varchar(50);index;default:''" json:"asset_family"`
	AssetSubtype            string `gorm:"type:varchar(50);default:''" json:"asset_subtype"`
	IsOnline                bool   `json:"is_online"`
	IsKey                   bool   `json:"is_key"`
	SecurityProtectionLevel string `gorm:"type:varchar(20)" json:"security_protection_level"`
	FilingCertNumber        string `gorm:"type:varchar(100)" json:"filing_cert_number"`
	IcpFilingNumber         string `gorm:"type:varchar(100)" json:"icp_filing_number"`
	PublicSecurityFiling    string `gorm:"type:varchar(100)" json:"public_security_filing"`

	// ── 地域（省市区县级编码，与 @vant/area-data 一致）──
	RegionCode string `gorm:"type:varchar(12);index" json:"region_code"`

	// ── 组织关联 ──
	OrganizeID        string `gorm:"type:varchar(64);index" json:"organize_id"`
	ConstructionOrgID string `gorm:"type:varchar(64)" json:"construction_org_id"`
	OperationOrgID    string `gorm:"type:varchar(64)" json:"operation_org_id"`

	// ── 审核与来源 ──
	ReviewStatus ReviewStatus   `gorm:"type:varchar(20)" json:"review_status"`
	DataSource   DataSourceType `gorm:"type:varchar(20)" json:"data_source"`

	// ── 责任人 ──
	ResponsibleUserID   string `gorm:"type:varchar(64)" json:"responsible_user_id"`
	ResponsibleUserName string `gorm:"type:varchar(100)" json:"responsible_user_name"`

	// ── 风险与扫描 ──
	RiskScore  float64    `gorm:"default:0;index" json:"risk_score"`
	VulnCount  int        `gorm:"default:0" json:"vuln_count"`
	LastScanAt *time.Time `json:"last_scan_at"`

	// ── 证书与过期 ──
	SSLExpiresAt    *time.Time `json:"ssl_expires_at"`
	DomainExpiresAt *time.Time `json:"domain_expires_at"`

	// ── 统计 ──
	EventsCount   int `gorm:"default:0" json:"events_count"`
	CircularCount int `gorm:"default:0" json:"circular_count"`

	// ── 扩展 ──
	Tags   StringArray `gorm:"type:text" json:"tags"`
	Extra  JSONMap     `gorm:"type:text" json:"extra"`
	Remark string      `gorm:"type:varchar(500)" json:"remark"`
}

func (Asset) TableName() string { return "vs_asset" }

// AssetGroup 资产分组
type AssetGroup struct {
	ID          string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name        string    `gorm:"type:varchar(200);not null" json:"name"`
	Description string    `gorm:"type:text" json:"description"`
	ParentID    string    `gorm:"type:varchar(36);index" json:"parent_id"`
	CreatedBy   string    `gorm:"type:varchar(64)" json:"created_by"`
	OrganizeID  string    `gorm:"type:varchar(64);index" json:"organize_id"`
	IsDynamic   bool      `gorm:"default:false" json:"is_dynamic"`
	RuleField   string    `gorm:"type:varchar(50)" json:"rule_field"`
	RuleOp      string    `gorm:"type:varchar(20)" json:"rule_op"`
	RuleValue   string    `gorm:"type:varchar(200)" json:"rule_value"`
	AssetCount  int64     `gorm:"default:0" json:"asset_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (AssetGroup) TableName() string { return "vs_asset_group" }

// ── 标签系统 ──

// Tag 标签定义
type Tag struct {
	ID        int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	Name      string    `gorm:"type:varchar(100);uniqueIndex;not null" json:"name"`
	Color     string    `gorm:"type:varchar(20);default:#1890ff" json:"color"`
	Category  string    `gorm:"type:varchar(50);index" json:"category"`
	IsAuto    bool      `gorm:"default:false" json:"is_auto"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Tag) TableName() string { return "vs_tag" }

// AssetTag 资产-标签关联
type AssetTag struct {
	ID        int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	AssetID   string    `gorm:"type:varchar(36);not null;uniqueIndex:idx_vs_asset_tag" json:"asset_id"`
	TagID     int64     `gorm:"not null;uniqueIndex:idx_vs_asset_tag" json:"tag_id"`
	Source    string    `gorm:"type:varchar(30);default:manual" json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

func (AssetTag) TableName() string { return "vs_asset_tag" }

// AssetChangeLog 资产变更日志
type AssetChangeLog struct {
	ID         int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	AssetID    string    `gorm:"type:varchar(36);not null;index" json:"asset_id"`
	ChangeType string    `gorm:"type:varchar(30);not null;index" json:"change_type"`
	Field      string    `gorm:"type:varchar(50)" json:"field"`
	OldValue   string    `gorm:"type:text" json:"old_value"`
	NewValue   string    `gorm:"type:text" json:"new_value"`
	Source     string    `gorm:"type:varchar(30)" json:"source"`
	Operator   string    `gorm:"type:varchar(64)" json:"operator"`
	CreatedAt  time.Time `json:"created_at"`
}

func (AssetChangeLog) TableName() string { return "vs_asset_change_log" }

// AssetRiskHistory 资产风险评分历史
type AssetRiskHistory struct {
	ID            int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	AssetID       string    `gorm:"type:varchar(36);not null;index" json:"asset_id"`
	Score         float64   `gorm:"default:0" json:"score"`
	VulnScore     float64   `json:"vuln_score"`
	ExposureScore float64   `json:"exposure_score"`
	AlertScore    float64   `json:"alert_score"`
	SSLScore      float64   `json:"ssl_score"`
	RecordedAt    time.Time `gorm:"index" json:"recorded_at"`
}

func (AssetRiskHistory) TableName() string { return "vs_asset_risk_history" }

// ── 组织管理 ──

// Organize 组织单位
type Organize struct {
	ID                        string     `gorm:"primarykey;type:varchar(36)" json:"id"`
	ParentID                  string     `gorm:"type:varchar(36);index" json:"parent_id"`
	Name                      string     `gorm:"type:varchar(200);not null" json:"name"`
	UnifiedSocialCreditCode   string     `gorm:"type:varchar(50);uniqueIndex" json:"unified_social_credit_code"`
	IndustryCategory          string     `gorm:"type:varchar(100)" json:"industry_category"`
	UnitType                  string     `gorm:"type:varchar(50)" json:"unit_type"`
	IsNotificationMember      bool       `gorm:"default:false" json:"is_notification_member"`
	Address                   string     `gorm:"type:varchar(500)" json:"address"`
	UnitDetailAddress         string     `gorm:"type:varchar(500)" json:"unit_detail_address"`
	LeaderName                string     `gorm:"type:varchar(100)" json:"leader_name"`
	LeaderTitle               string     `gorm:"type:varchar(100)" json:"leader_title"`
	ResponsibleDepartmentName string     `gorm:"type:varchar(200)" json:"responsible_department_name"`
	DepartmentLeaderName      string     `gorm:"type:varchar(100)" json:"department_leader_name"`
	DepartmentLeaderTitle     string     `gorm:"type:varchar(100)" json:"department_leader_title"`
	DepartmentLeaderPhone     string     `gorm:"type:varchar(30)" json:"department_leader_phone"`
	ContactName               string     `gorm:"type:varchar(100)" json:"contact_name"`
	ContactTitle              string     `gorm:"type:varchar(100)" json:"contact_title"`
	ContactPhone              string     `gorm:"type:varchar(30)" json:"contact_phone"`
	AssetCount                int64      `gorm:"default:0" json:"asset_count"`
	DeletedAt                 *time.Time `gorm:"index" json:"deleted_at"`
	CreatedBy                 string     `gorm:"type:varchar(64)" json:"created_by"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
}

func (Organize) TableName() string { return "vs_organize" }

// ConstructionOrg 建设/运维单位
type ConstructionOrg struct {
	ID             string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name           string    `gorm:"type:varchar(200);not null" json:"name"`
	Location       string    `gorm:"type:varchar(200)" json:"location"`
	Address        string    `gorm:"type:varchar(300)" json:"address"`
	ChargePerson   string    `gorm:"type:varchar(100)" json:"charge_person"`
	ChargePhone    string    `gorm:"type:varchar(30)" json:"charge_phone"`
	SecurityFiling string    `gorm:"type:varchar(100)" json:"security_filing"`
	Used           int       `gorm:"default:0" json:"used"`
	CreatedBy      string    `gorm:"type:varchar(64)" json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (ConstructionOrg) TableName() string { return "vs_construction_org" }

// ── 生命周期 ──

// AssetLifecycle 生命周期变更记录
type AssetLifecycle struct {
	ID        int64          `gorm:"primaryKey;autoIncrement" json:"id"`
	AssetID   string         `gorm:"type:varchar(36);not null;index" json:"asset_id"`
	FromState LifecycleState `gorm:"type:varchar(30)" json:"from_state"`
	ToState   LifecycleState `gorm:"type:varchar(30);not null" json:"to_state"`
	Operator  string         `gorm:"type:varchar(64)" json:"operator"`
	Remark    string         `gorm:"type:varchar(500)" json:"remark"`
	CreatedAt time.Time      `json:"created_at"`
}

func (AssetLifecycle) TableName() string { return "vs_asset_lifecycle" }

// AssetCompliance 资产合规项
type AssetCompliance struct {
	ID         int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	AssetID    string     `gorm:"type:varchar(36);not null;index" json:"asset_id"`
	ItemName   string     `gorm:"type:varchar(100);not null" json:"item_name"`
	ItemType   string     `gorm:"type:varchar(50);index" json:"item_type"`
	Status     string     `gorm:"type:varchar(20);default:unchecked" json:"status"`
	ExpiresAt  *time.Time `json:"expires_at"`
	VerifiedAt *time.Time `json:"verified_at"`
	VerifiedBy string     `gorm:"type:varchar(64)" json:"verified_by"`
	Remark     string     `gorm:"type:varchar(500)" json:"remark"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func (AssetCompliance) TableName() string { return "vs_asset_compliance" }

// AssetResponsible 资产责任人
type AssetResponsible struct {
	ID           int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	AssetID      string    `gorm:"type:varchar(36);not null;index" json:"asset_id"`
	UserID       string    `gorm:"type:varchar(64)" json:"user_id"`
	UserName     string    `gorm:"type:varchar(100)" json:"user_name"`
	Phone        string    `gorm:"type:varchar(30)" json:"phone"`
	Role         string    `gorm:"type:varchar(50)" json:"role"`
	OrganizeID   string    `gorm:"type:varchar(64)" json:"organize_id"`
	OrganizeName string    `gorm:"type:varchar(200)" json:"organize_name"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (AssetResponsible) TableName() string { return "vs_asset_responsible" }

// ── 风险评估 ──

// AssetRiskScore 资产风险评分
type AssetRiskScore struct {
	ID              int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	AssetID         string     `gorm:"type:varchar(36);uniqueIndex;not null" json:"asset_id"`
	TotalScore      float64    `gorm:"default:0" json:"total_score"`
	ExposureScore   float64    `gorm:"default:0" json:"exposure_score"`
	VulnScore       float64    `gorm:"default:0" json:"vuln_score"`
	ComplianceScore float64    `gorm:"default:0" json:"compliance_score"`
	OpenPorts       int        `gorm:"default:0" json:"open_ports"`
	VulnCount       int        `gorm:"default:0" json:"vuln_count"`
	CriticalVulns   int        `gorm:"default:0" json:"critical_vulns"`
	LastScanAt      *time.Time `json:"last_scan_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (AssetRiskScore) TableName() string { return "vs_asset_risk_score" }

// Alert 安全告警
type Alert struct {
	ID          string        `gorm:"primarykey;type:varchar(36)" json:"id"`
	AssetID     string        `gorm:"type:varchar(36);index" json:"asset_id"`
	AlertType   string        `gorm:"type:varchar(50);index" json:"alert_type"`
	Severity    SeverityLevel `gorm:"type:varchar(20);index" json:"severity"`
	Title       string        `gorm:"type:varchar(300);not null" json:"title"`
	Description string        `gorm:"type:text" json:"description"`
	Source      string        `gorm:"type:varchar(50)" json:"source"`
	Status      AlertStatus   `gorm:"type:varchar(20);default:open;index" json:"status"`
	AckedBy     string        `gorm:"type:varchar(64)" json:"acked_by"`
	AckedAt     *time.Time    `json:"acked_at"`
	ResolvedAt  *time.Time    `json:"resolved_at"`
	CreatedBy   string        `gorm:"type:varchar(64)" json:"created_by"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

func (Alert) TableName() string { return "vs_alert" }

// ── 资产审核 ──

// AssetVerify 资产审核记录
type AssetVerify struct {
	ID           string         `gorm:"primarykey;type:varchar(36)" json:"id"`
	AssetID      string         `gorm:"type:varchar(36);index" json:"asset_id"`
	OrganizeID   string         `gorm:"type:varchar(64);index" json:"organize_id"`
	ReviewStatus ReviewStatus   `gorm:"type:varchar(20);default:pending" json:"review_status"`
	ReviewRemark string         `gorm:"type:varchar(500)" json:"review_remark"`
	ReviewBy     string         `gorm:"type:varchar(64)" json:"review_by"`
	DataSource   DataSourceType `gorm:"type:varchar(20)" json:"data_source"`
	CreatedBy    string         `gorm:"type:varchar(64)" json:"created_by"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

func (AssetVerify) TableName() string { return "vs_asset_verify" }

type AssetVerifyTaskStatus = string

const (
	AssetVerifyTaskPendingDispatch AssetVerifyTaskStatus = "pending_dispatch"
	AssetVerifyTaskPendingReceive  AssetVerifyTaskStatus = "pending_receive"
	AssetVerifyTaskPendingVerify   AssetVerifyTaskStatus = "pending_verify"
	AssetVerifyTaskConfirmed       AssetVerifyTaskStatus = "confirmed"
	AssetVerifyTaskRejected        AssetVerifyTaskStatus = "rejected"
	AssetVerifyTaskReturned        AssetVerifyTaskStatus = "returned"
	AssetVerifyTaskForwarded       AssetVerifyTaskStatus = "forwarded"
	AssetVerifyTaskArchived        AssetVerifyTaskStatus = "archived"
)

type AssetVerifyTaskAction = string

const (
	AssetVerifyActionCreate     AssetVerifyTaskAction = "create"
	AssetVerifyActionDispatch   AssetVerifyTaskAction = "dispatch"
	AssetVerifyActionReceive    AssetVerifyTaskAction = "receive"
	AssetVerifyActionConfirm    AssetVerifyTaskAction = "verify_confirm"
	AssetVerifyActionReject     AssetVerifyTaskAction = "verify_reject"
	AssetVerifyActionForward    AssetVerifyTaskAction = "forward"
	AssetVerifyActionReturn     AssetVerifyTaskAction = "return"
	AssetVerifyActionArchive    AssetVerifyTaskAction = "archive"
	AssetVerifyActionReactivate AssetVerifyTaskAction = "reactivate"
)

type AssetVerifyResult = string

const (
	AssetVerifyResultConfirmed    AssetVerifyResult = "confirmed"
	AssetVerifyResultNotConfirmed AssetVerifyResult = "not_confirmed"
)

// AssetVerifyTask tracks the operational verification workflow for one asset.
type AssetVerifyTask struct {
	ID                string                `gorm:"primarykey;type:varchar(36)" json:"id"`
	AssetID           string                `gorm:"type:varchar(36);not null;index" json:"asset_id"`
	BatchID           string                `gorm:"type:varchar(36);index" json:"batch_id"`
	SourceType        string                `gorm:"type:varchar(30);index" json:"source_type"`
	Status            AssetVerifyTaskStatus `gorm:"type:varchar(30);index" json:"status"`
	OwnerOrganizeID   string                `gorm:"type:varchar(64);index" json:"owner_organize_id"`
	CurrentOrganizeID string                `gorm:"type:varchar(64);index" json:"current_organize_id"`
	FromOrganizeID    string                `gorm:"type:varchar(64)" json:"from_organize_id"`
	TargetOrganizeID  string                `gorm:"type:varchar(64)" json:"target_organize_id"`
	ConstructionOrgID string                `gorm:"type:varchar(64)" json:"construction_org_id"`
	OperationOrgID    string                `gorm:"type:varchar(64)" json:"operation_org_id"`
	VerifyResult      AssetVerifyResult     `gorm:"type:varchar(30)" json:"verify_result"`
	RejectReason      string                `gorm:"type:varchar(500)" json:"reject_reason"`
	Remark            string                `gorm:"type:varchar(500)" json:"remark"`
	ArchivedAt        *time.Time            `json:"archived_at"`
	CreatedBy         string                `gorm:"type:varchar(64)" json:"created_by"`
	UpdatedBy         string                `gorm:"type:varchar(64)" json:"updated_by"`
	CreatedAt         time.Time             `json:"created_at"`
	UpdatedAt         time.Time             `json:"updated_at"`
}

func (AssetVerifyTask) TableName() string { return "vs_asset_verify_task" }

// AssetVerifyOplog records every state transition of asset verification tasks.
type AssetVerifyOplog struct {
	ID               int64                 `gorm:"primaryKey;autoIncrement" json:"id"`
	TaskID           string                `gorm:"type:varchar(36);not null;index" json:"task_id"`
	AssetID          string                `gorm:"type:varchar(36);not null;index" json:"asset_id"`
	Action           AssetVerifyTaskAction `gorm:"type:varchar(30);not null;index" json:"action"`
	FromStatus       string                `gorm:"type:varchar(30)" json:"from_status"`
	ToStatus         string                `gorm:"type:varchar(30)" json:"to_status"`
	FromOrganizeID   string                `gorm:"type:varchar(64)" json:"from_organize_id"`
	TargetOrganizeID string                `gorm:"type:varchar(64)" json:"target_organize_id"`
	Operator         string                `gorm:"type:varchar(64)" json:"operator"`
	Remark           string                `gorm:"type:varchar(500)" json:"remark"`
	CreatedAt        time.Time             `json:"created_at"`
}

func (AssetVerifyOplog) TableName() string { return "vs_asset_verify_oplog" }

// AssetArchiveSnapshot keeps immutable data captured when an asset is archived.
type AssetArchiveSnapshot struct {
	ID         string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	TaskID     string    `gorm:"type:varchar(36);not null;index" json:"task_id"`
	AssetID    string    `gorm:"type:varchar(36);not null;index" json:"asset_id"`
	BatchID    string    `gorm:"type:varchar(36);index" json:"batch_id"`
	OrganizeID string    `gorm:"type:varchar(64);index" json:"organize_id"`
	AssetName  string    `gorm:"type:varchar(200)" json:"asset_name"`
	Address    string    `gorm:"type:varchar(500)" json:"address"`
	Status     string    `gorm:"type:varchar(30);index" json:"status"`
	Snapshot   JSONMap   `gorm:"type:text" json:"snapshot"`
	ArchivedBy string    `gorm:"type:varchar(64)" json:"archived_by"`
	ArchivedAt time.Time `json:"archived_at"`
	CreatedAt  time.Time `json:"created_at"`
}

func (AssetArchiveSnapshot) TableName() string { return "vs_asset_archive_snapshot" }

// ── 合规模板 ──

// ComplianceTemplate 合规检查模板
type ComplianceTemplate struct {
	ID          int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	Name        string    `gorm:"type:varchar(200);not null" json:"name"`
	Standard    string    `gorm:"type:varchar(50);not null;index" json:"standard"`
	Version     string    `gorm:"type:varchar(20)" json:"version"`
	Description string    `gorm:"type:text" json:"description"`
	TotalItems  int       `gorm:"default:0" json:"total_items"`
	Enabled     bool      `gorm:"default:true" json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (ComplianceTemplate) TableName() string { return "vs_compliance_template" }

// ComplianceTemplateItem 合规模板检查项
type ComplianceTemplateItem struct {
	ID          int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	TemplateID  int64     `gorm:"not null;index" json:"template_id"`
	Category    string    `gorm:"type:varchar(100)" json:"category"`
	SubCategory string    `gorm:"type:varchar(100)" json:"sub_category"`
	ItemCode    string    `gorm:"type:varchar(50)" json:"item_code"`
	ItemName    string    `gorm:"type:varchar(300);not null" json:"item_name"`
	Description string    `gorm:"type:text" json:"description"`
	Requirement string    `gorm:"type:text" json:"requirement"`
	CheckMethod string    `gorm:"type:text" json:"check_method"`
	Level       string    `gorm:"type:varchar(20)" json:"level"`
	SortOrder   int       `gorm:"default:0" json:"sort_order"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (ComplianceTemplateItem) TableName() string { return "vs_compliance_template_item" }

// ComplianceCheckResult 合规检查结果
type ComplianceCheckResult struct {
	ID         int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	AssetID    string    `gorm:"type:varchar(36);not null;index" json:"asset_id"`
	TemplateID int64     `gorm:"not null;index" json:"template_id"`
	ItemID     int64     `gorm:"not null;index" json:"item_id"`
	Status     string    `gorm:"type:varchar(20);default:unchecked" json:"status"`
	Evidence   string    `gorm:"type:text" json:"evidence"`
	Remark     string    `gorm:"type:varchar(500)" json:"remark"`
	CheckedBy  string    `gorm:"type:varchar(64)" json:"checked_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (ComplianceCheckResult) TableName() string { return "vs_compliance_check_result" }

// ── 集成管理 ──

// IntegrationSource 外部数据源
type IntegrationSource struct {
	ID        int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	Name      string     `gorm:"type:varchar(100);not null" json:"name"`
	Module    string     `gorm:"type:varchar(50);not null;index" json:"module"`
	BaseURL   string     `gorm:"type:varchar(500)" json:"base_url"`
	APIKey    string     `gorm:"type:varchar(200)" json:"api_key"`
	Enabled   bool       `gorm:"default:true" json:"enabled"`
	SyncCron  string     `gorm:"type:varchar(50)" json:"sync_cron"`
	LastSync  *time.Time `json:"last_sync"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

func (IntegrationSource) TableName() string { return "vs_integration_source" }

// IntegrationEvent 集成事件
type IntegrationEvent struct {
	ID        int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	SourceID  int64     `gorm:"index" json:"source_id"`
	Module    string    `gorm:"type:varchar(50);index" json:"module"`
	EventType string    `gorm:"type:varchar(50);index" json:"event_type"`
	AssetID   string    `gorm:"type:varchar(36);index" json:"asset_id"`
	Payload   string    `gorm:"type:text" json:"payload"`
	Status    string    `gorm:"type:varchar(20);default:pending;index" json:"status"`
	ErrorMsg  string    `gorm:"type:text" json:"error_msg"`
	CreatedAt time.Time `json:"created_at"`
}

func (IntegrationEvent) TableName() string { return "vs_integration_event" }

// ── 自动化工作流 ──

// Workflow 自动化工作流
type Workflow struct {
	ID          string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name        string    `gorm:"type:varchar(200);not null" json:"name"`
	Description string    `gorm:"type:text" json:"description"`
	TriggerType string    `gorm:"type:varchar(50);index" json:"trigger_type"`
	TriggerCond string    `gorm:"type:text" json:"trigger_cond"`
	Actions     string    `gorm:"type:text" json:"actions"`
	Enabled     bool      `gorm:"default:true" json:"enabled"`
	CreatedBy   string    `gorm:"type:varchar(64)" json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (Workflow) TableName() string { return "vs_workflow" }

// WorkflowExecution 工作流执行记录
type WorkflowExecution struct {
	ID         int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	WorkflowID string     `gorm:"type:varchar(36);index" json:"workflow_id"`
	TriggerBy  string     `gorm:"type:varchar(100)" json:"trigger_by"`
	Status     string     `gorm:"type:varchar(20);default:pending" json:"status"`
	Input      string     `gorm:"type:text" json:"input"`
	Output     string     `gorm:"type:text" json:"output"`
	ErrorMsg   string     `gorm:"type:text" json:"error_msg"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (WorkflowExecution) TableName() string { return "vs_workflow_execution" }
