package model

import "time"

type ScanLog struct {
	ID        uint      `gorm:"primarykey;autoIncrement" json:"id"`
	TaskID    string    `gorm:"type:varchar(36);index;not null" json:"task_id"`
	Level     string    `gorm:"type:varchar(10);not null" json:"level"`
	Message   string    `gorm:"type:text;not null" json:"message"`
	Stage     string    `gorm:"type:varchar(50)" json:"stage"`
	Module    string    `gorm:"type:varchar(50)" json:"module"`
	CreatedAt time.Time `json:"created_at"`
}

func (ScanLog) TableName() string { return "vs_scan_log" }
