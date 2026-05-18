package model

import "time"

type ASMProject struct {
	BaseModel
	Name            string     `json:"name" gorm:"type:varchar(200);not null"`
	Description     string     `json:"description" gorm:"type:varchar(500)"`
	Schedule        string     `json:"schedule" gorm:"type:varchar(100)"`
	Enabled         bool       `json:"enabled" gorm:"default:true"`
	CollectorConfig JSONMap    `json:"collector_config" gorm:"type:text"`
	DiscoveryStatus string     `json:"discovery_status" gorm:"type:varchar(20);default:idle"`
	LastDiscoveryAt *time.Time `json:"last_discovery_at"`
}

func (ASMProject) TableName() string { return "asm_projects" }

type ASMSeed struct {
	ID        string     `json:"id" gorm:"primarykey;type:varchar(36)"`
	ProjectID string     `json:"project_id" gorm:"type:varchar(36);index;not null"`
	Type      string     `json:"type" gorm:"type:varchar(20);not null"`
	Value     string     `json:"value" gorm:"type:varchar(500);not null"`
	Config    JSONMap    `json:"config" gorm:"type:text"`
	Enabled   bool       `json:"enabled" gorm:"default:true"`
	LastRunAt *time.Time `json:"last_run_at"`
	CreatedAt time.Time  `json:"created_at"`
}

func (ASMSeed) TableName() string { return "asm_seeds" }

type ASMDiscoveredAsset struct {
	ID         string    `json:"id" gorm:"primarykey;type:varchar(36)"`
	ProjectID  string    `json:"project_id" gorm:"type:varchar(36);index;not null"`
	Type       string    `json:"type" gorm:"type:varchar(30);index"`
	Value      string    `json:"value" gorm:"type:varchar(500);index"`
	Source     string    `json:"source" gorm:"type:varchar(50)"`
	Attributes JSONMap   `json:"attributes" gorm:"type:text"`
	RiskScore  int       `json:"risk_score" gorm:"default:0"`
	Status     string    `json:"status" gorm:"type:varchar(20);default:active"`
	AssetID    string    `json:"asset_id" gorm:"type:varchar(36);index"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

func (ASMDiscoveredAsset) TableName() string { return "asm_discovered_assets" }

type ASMChange struct {
	ID        string    `json:"id" gorm:"primarykey;type:varchar(36)"`
	ProjectID string    `json:"project_id" gorm:"type:varchar(36);index"`
	AssetID   string    `json:"asset_id" gorm:"type:varchar(36);index"`
	Field     string    `json:"field" gorm:"type:varchar(100)"`
	OldValue  string    `json:"old_value" gorm:"type:text"`
	NewValue  string    `json:"new_value" gorm:"type:text"`
	Severity  string    `json:"severity" gorm:"type:varchar(20)"`
	ChangeAt  time.Time `json:"change_at"`
}

func (ASMChange) TableName() string { return "asm_changes" }

type ASMAlertRule struct {
	ID        string    `json:"id" gorm:"primarykey;type:varchar(36)"`
	ProjectID string    `json:"project_id" gorm:"type:varchar(36);index"`
	Name      string    `json:"name" gorm:"type:varchar(200)"`
	Type      string    `json:"type" gorm:"type:varchar(50)"`
	Condition JSONMap   `json:"condition" gorm:"type:text"`
	Actions   JSONMap   `json:"actions" gorm:"type:text"`
	Enabled   bool      `json:"enabled" gorm:"default:true"`
	CreatedAt time.Time `json:"created_at"`
}

func (ASMAlertRule) TableName() string { return "asm_alert_rules" }
