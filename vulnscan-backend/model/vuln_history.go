package model

import "time"

type VulnStatusHistory struct {
	ID        string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	VulnID    string    `gorm:"type:varchar(36);index;not null" json:"vuln_id"`
	OldStatus string    `gorm:"type:varchar(20)" json:"old_status"`
	NewStatus string    `gorm:"type:varchar(20)" json:"new_status"`
	Comment   string    `gorm:"type:text" json:"comment"`
	Operator  string    `gorm:"type:varchar(64)" json:"operator"`
	CreatedAt time.Time `json:"created_at"`
}

func (VulnStatusHistory) TableName() string { return "vs_vuln_status_history" }
