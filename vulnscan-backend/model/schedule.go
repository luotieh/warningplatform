package model

import "time"

type ScanSchedule struct {
	ID           string      `gorm:"primarykey;type:varchar(36)" json:"id"`
	Name         string      `gorm:"type:varchar(200);not null" json:"name"`
	Description  string      `gorm:"type:text" json:"description"`
	TemplateID   string      `gorm:"type:varchar(36)" json:"template_id"`
	TemplateName string      `gorm:"type:varchar(200)" json:"template_name"`
	Targets      StringArray `gorm:"type:text" json:"targets"`
	Config       JSONMap     `gorm:"type:text" json:"config"`

	ScheduleType string `gorm:"type:varchar(20);not null" json:"schedule_type"`
	CronExpr     string `gorm:"type:varchar(100)" json:"cron_expr"`
	IntervalMin  int    `gorm:"default:0" json:"interval_min"`

	Enabled    bool       `gorm:"default:true" json:"enabled"`
	Status     string     `gorm:"type:varchar(20);default:'idle'" json:"status"`
	LastRunAt  *time.Time `json:"last_run_at"`
	NextRunAt  *time.Time `json:"next_run_at"`
	LastTaskID string     `gorm:"type:varchar(36)" json:"last_task_id"`
	RunCount   int64      `gorm:"default:0" json:"run_count"`

	CreatedBy  string    `gorm:"type:varchar(64)" json:"created_by"`
	OrganizeID string    `gorm:"type:varchar(64);index" json:"organize_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (ScanSchedule) TableName() string { return "vs_scan_schedule" }

const (
	ScheduleTypeCron     = "cron"
	ScheduleTypeInterval = "interval"
	ScheduleTypeDaily    = "daily"
	ScheduleTypeWeekly   = "weekly"
	ScheduleTypeMonthly  = "monthly"

	ScheduleStatusIdle    = "idle"
	ScheduleStatusRunning = "running"
)
