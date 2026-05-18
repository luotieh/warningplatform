package model

import "time"

type ScanTask struct {
	ID            string      `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name          string      `gorm:"type:varchar(200);not null" json:"name"`
	TemplateID    string      `gorm:"type:varchar(36);index" json:"template_id"`
	TemplateName  string      `gorm:"type:varchar(200)" json:"template_name"`
	Type          string      `gorm:"type:varchar(50);index" json:"type"`
	Targets       StringArray `gorm:"type:text" json:"targets"`
	Config        JSONMap     `gorm:"type:text" json:"config"`
	Parameters    JSONMap     `gorm:"type:text" json:"parameters"`
	Priority      int         `gorm:"default:5" json:"priority"`
	Status        string      `gorm:"type:varchar(20);index;default:'pending'" json:"status"`
	Progress      float64     `gorm:"default:0" json:"progress"`
	CurrentStage  string      `gorm:"type:varchar(100)" json:"current_stage"`
	CurrentModule string      `gorm:"type:varchar(100)" json:"current_module"`

	TotalTargets   int `gorm:"default:0" json:"total_targets"`
	ScannedTargets int `gorm:"default:0" json:"scanned_targets"`
	VulnCritical   int `gorm:"default:0" json:"vuln_critical"`
	VulnHigh       int `gorm:"default:0" json:"vuln_high"`
	VulnMedium     int `gorm:"default:0" json:"vuln_medium"`
	VulnLow        int `gorm:"default:0" json:"vuln_low"`
	VulnInfo       int `gorm:"default:0" json:"vuln_info"`
	AliveHosts     int `gorm:"default:0" json:"alive_hosts"`
	OpenPorts      int `gorm:"default:0" json:"open_ports"`

	ParentID   string     `gorm:"type:varchar(36);index" json:"parent_id"`
	SubCount   int        `gorm:"default:0" json:"sub_count"`
	Profile    string     `gorm:"type:varchar(50);default:'full'" json:"profile"`
	WorkerID   string     `gorm:"type:varchar(36);index" json:"worker_id"`
	ScheduleID string     `gorm:"type:varchar(36)" json:"schedule_id"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	ErrorMsg   string     `gorm:"type:text" json:"error_msg"`
	CreatedBy  string     `gorm:"type:varchar(64)" json:"created_by"`
	OrganizeID string     `gorm:"type:varchar(64);index" json:"organize_id"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func (ScanTask) TableName() string { return "vs_scan_task" }

const (
	TaskStatusPending   = "pending"
	TaskStatusQueued    = "queued"
	TaskStatusRunning   = "running"
	TaskStatusPaused    = "paused"
	TaskStatusCompleted = "completed"
	TaskStatusFailed    = "failed"
	TaskStatusCancelled = "cancelled"

	TaskStatusSplitting = "splitting"
	TaskStatusPartial   = "partial"

	TaskTypeAssetEnrich = "asset_enrich"
	TaskTypeVulnRetest  = "vuln_retest"
)
