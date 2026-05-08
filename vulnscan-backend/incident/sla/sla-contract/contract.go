package slaContract

import (
	"context"
	"time"
)

type ServiceSLA interface {
	GetSLAOverview(ctx context.Context) (*SLAOverviewResp, error)
	SetSLA(ctx context.Context, req SLASetReq) error
	CheckAndUpdateSLA(ctx context.Context) (*SLACheckResult, error)
}

type SLASetReq struct {
	ID       string `json:"id" binding:"required"`
	SLALevel int    `json:"sla_level" binding:"required,min=1,max=3"`
}

type SLAOverviewResp struct {
	TotalTracked      int64             `json:"total_tracked"`
	NormalCount       int64             `json:"normal_count"`
	WarningCount      int64             `json:"warning_count"`
	BreachedCount     int64             `json:"breached_count"`
	EscalatedCount    int64             `json:"escalated_count"`
	ComplianceRate    float64           `json:"compliance_rate"`
	UpcomingDeadlines []SLADeadlineItem `json:"upcoming_deadlines"`
}

type SLADeadlineItem struct {
	IncidentId   string    `json:"incident_id"`
	IncidentNo   string    `json:"incident_no"`
	IncidentName string    `json:"incident_name"`
	Level        int       `json:"level"`
	SLALevel     int       `json:"sla_level"`
	SLADeadline  time.Time `json:"sla_deadline"`
	RemainingMin int       `json:"remaining_min"`
	Status       int       `json:"status"`
}

type SLACheckResult struct {
	TotalChecked int `json:"total_checked"`
	Updated      int `json:"updated"`
	Warned       int `json:"warned"`
	Breached     int `json:"breached"`
	Escalated    int `json:"escalated"`
}
