package model

import "time"

type ScanTemplate struct {
	ID          string      `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name        string      `gorm:"type:varchar(200);not null" json:"name"`
	Code        string      `gorm:"type:varchar(100);uniqueIndex" json:"code"`
	Category    string      `gorm:"type:varchar(50);index" json:"category"`
	Description string      `gorm:"type:text" json:"description"`
	Icon        string      `gorm:"type:varchar(50)" json:"icon"`
	Tags        StringArray `gorm:"type:text" json:"tags"`
	Content     string      `gorm:"type:text" json:"content"`
	Version     string      `gorm:"type:varchar(20)" json:"version"`
	Builtin     bool        `gorm:"default:false" json:"builtin"`
	ParentID    string      `gorm:"type:varchar(36)" json:"parent_id"`
	Enabled     bool        `gorm:"default:true" json:"enabled"`
	UsageCount  int64       `gorm:"default:0" json:"usage_count"`
	AuthorID    string      `gorm:"type:varchar(64)" json:"author_id"`
	OrganizeID  string      `gorm:"type:varchar(64);index" json:"organize_id"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

func (ScanTemplate) TableName() string { return "vs_scan_template" }
