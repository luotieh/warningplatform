package model

import "time"

type FPRule struct {
	ID         string    `gorm:"primarykey;type:varchar(26)" json:"id"`
	Name       string    `gorm:"type:varchar(128)" json:"name"`
	MatchType  string    `gorm:"type:varchar(32);not null;index" json:"match_type" binding:"required"`
	MatchField string    `gorm:"type:varchar(64);not null" json:"match_field"`
	MatchValue string    `gorm:"type:varchar(512);not null" json:"match_value" binding:"required"`
	Reason     string    `gorm:"type:text" json:"reason"`
	SourceID   string    `gorm:"type:varchar(26);index" json:"source_id"`
	Scope      string    `gorm:"type:varchar(32);default:global" json:"scope"`
	Enabled    bool      `gorm:"default:true" json:"enabled"`
	HitCount   int       `gorm:"default:0" json:"hit_count"`
	CreatedBy  string    `gorm:"type:varchar(64)" json:"created_by"`
	OrganizeID string    `gorm:"type:varchar(64);index" json:"organize_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (FPRule) TableName() string { return "vs_fp_rule" }

const (
	FPMatchTypeFingerprint  = "fingerprint"
	FPMatchTypeTargetType   = "target_type"
	FPMatchTypeModuleType   = "module_type"
	FPMatchTypeTitlePattern = "title_pattern"
)
