package model

import "time"

type ScanExclusion struct {
	ID          string    `gorm:"primarykey;type:varchar(26)" json:"id"`
	Name        string    `gorm:"type:varchar(128);not null" json:"name" binding:"required"`
	RuleType    string    `gorm:"type:varchar(32);not null;index" json:"rule_type" binding:"required"`
	MatchValue  string    `gorm:"type:varchar(512);not null" json:"match_value" binding:"required"`
	Description string    `gorm:"type:text" json:"description"`
	Scope       string    `gorm:"type:varchar(32);default:global" json:"scope"`
	Enabled     bool      `gorm:"default:true" json:"enabled"`
	HitCount    int       `gorm:"default:0" json:"hit_count"`
	CreatedBy   string    `gorm:"type:varchar(64)" json:"created_by"`
	OrganizeID  string    `gorm:"type:varchar(64);index" json:"organize_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (ScanExclusion) TableName() string { return "vs_scan_exclusion" }

const (
	ExclusionRuleTypeTarget      = "target"
	ExclusionRuleTypePort        = "port"
	ExclusionRuleTypePath        = "path"
	ExclusionRuleTypeModule      = "module"
	ExclusionRuleTypeFindingType = "finding_type"

	ExclusionScopeGlobal = "global"
)
