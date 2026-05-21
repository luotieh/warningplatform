package model

import "time"

const (
	AssetDiscoveryProbePending   = "pending"
	AssetDiscoveryProbeRunning   = "running"
	AssetDiscoveryProbeCompleted = "completed"
	AssetDiscoveryProbeFailed    = "failed"
	AssetDiscoveryProbeCancelled = "cancelled"

	AssetDiscoveryCandidatePending   = "pending"
	AssetDiscoveryCandidateVerified  = "verified"
	AssetDiscoveryCandidateRejected  = "rejected"
	AssetDiscoveryCandidateImported  = "imported"
	AssetDiscoveryCandidateInLibrary = "in_library" // 台账中已存在，无需下发核验/重复入库
)

// AssetDiscoveryProbe 资产探测任务（关联扫描引擎任务，仅信息收集阶段）。
type AssetDiscoveryProbe struct {
	ID             string     `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name           string     `gorm:"type:varchar(200);not null" json:"name"`
	TaskID         string     `gorm:"type:varchar(36);index" json:"task_id"`
	TargetsRaw     string     `gorm:"type:text" json:"targets_raw"`
	TargetCount    int        `gorm:"default:0" json:"target_count"`
	PortsPreset    string     `gorm:"type:varchar(32);default:'top1000'" json:"ports_preset"`
	Status         string     `gorm:"type:varchar(20);index;default:'pending'" json:"status"`
	CandidateTotal int        `gorm:"default:0" json:"candidate_total"`
	PendingCount   int        `gorm:"default:0" json:"pending_count"`
	VerifiedCount  int        `gorm:"default:0" json:"verified_count"`
	ImportedCount  int        `gorm:"default:0" json:"imported_count"`
	ErrorMsg       string     `gorm:"type:text" json:"error_msg"`
	CreatedBy      string     `gorm:"type:varchar(64)" json:"created_by"`
	OrganizeID     string     `gorm:"type:varchar(64);index" json:"organize_id"`
	StartedAt      *time.Time `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (AssetDiscoveryProbe) TableName() string { return "vs_asset_discovery_probe" }

// AssetDiscoveryCandidate 探测候选资产，核验通过后可入库。
type AssetDiscoveryCandidate struct {
	ID                   string     `gorm:"primarykey;type:varchar(36)" json:"id"`
	ProbeID              string     `gorm:"type:varchar(36);index;not null" json:"probe_id"`
	TaskID               string     `gorm:"type:varchar(36);index" json:"task_id"`
	Address              string     `gorm:"type:varchar(500);index;not null" json:"address"`
	Port                 int        `gorm:"default:0;index" json:"port"`
	Protocol             string     `gorm:"type:varchar(20)" json:"protocol"`
	Service              string     `gorm:"type:varchar(100)" json:"service"`
	Version              string     `gorm:"type:varchar(100)" json:"version"`
	AssetType            string     `gorm:"type:varchar(50)" json:"asset_type"`
	Alive                bool       `gorm:"default:false" json:"alive"`
	Title                string     `gorm:"type:varchar(300)" json:"title"`
	Evidence             string     `gorm:"type:text" json:"evidence"`
	Status               string     `gorm:"type:varchar(20);index;default:'pending'" json:"status"`
	TargetOrganizeID     string     `gorm:"type:varchar(64);index" json:"target_organize_id"`
	TargetOrganizeName   string     `gorm:"-" json:"target_organize_name,omitempty"`
	InAssetLibrary       bool       `gorm:"-" json:"in_asset_library"`
	ExistingAssetID      string     `gorm:"-" json:"existing_asset_id,omitempty"`
	ExistingOrganizeID   string     `gorm:"-" json:"existing_organize_id,omitempty"`
	ExistingOrganizeName string     `gorm:"-" json:"existing_organize_name,omitempty"`
	ImportedID           string     `gorm:"type:varchar(36);index" json:"imported_asset_id"`
	VerifyRemark         string     `gorm:"type:varchar(500)" json:"verify_remark"`
	VerifiedBy           string     `gorm:"type:varchar(64)" json:"verified_by"`
	VerifiedAt           *time.Time `json:"verified_at"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

func (AssetDiscoveryCandidate) TableName() string { return "vs_asset_discovery_candidate" }
