package model

import "time"

type SystemSetting struct {
	Key         string    `gorm:"primarykey;type:varchar(128)" json:"key"`
	Value       string    `gorm:"type:text" json:"value"`
	Group       string    `gorm:"type:varchar(64);index" json:"group"`
	Label       string    `gorm:"type:varchar(128)" json:"label"`
	Description string    `gorm:"type:varchar(512)" json:"description"`
	ValueType   string    `gorm:"type:varchar(32);default:string" json:"value_type"` // string, int, bool, json
	IsSecret    bool      `gorm:"default:false" json:"is_secret"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `gorm:"type:varchar(64)" json:"updated_by"`
}
