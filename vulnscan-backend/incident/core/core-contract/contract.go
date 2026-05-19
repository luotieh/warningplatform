package coreContract

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type ServiceCore interface {
	CreateIncident(ctx context.Context, req IncidentCreateReq, createdBy string, organizeID string) error
	UpdateIncident(ctx context.Context, id string, req IncidentUpdateReq) error
	DeleteIncident(ctx context.Context, id string) error
	GetIncidentDetail(ctx context.Context, id string) (*IncidentDetailResp, error)
	ListIncidents(ctx context.Context, req IncidentListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]IncidentListItem, int64, error)

	GetDashboardStats(ctx context.Context) (*DashboardStatsResp, error)
	GetChartByType(ctx context.Context) ([]ChartTypeItem, error)
	GetChartByLevel(ctx context.Context) ([]ChartLevelItem, error)
	GetChartByTrend(ctx context.Context, rangeType string) ([]ChartTrendItem, error)

	GetOplogsByIncidentId(ctx context.Context, incidentId string) ([]OplogItem, error)
	GetOplogsByIncidentNo(ctx context.Context, incidentNo string) ([]OplogItem, error)
	ReceiveCallbackOplog(ctx context.Context, req OplogCallbackReq) error
}

type IncidentCreateReq struct {
	Name       string           `json:"name" binding:"required"`
	Level      int              `json:"level" binding:"required,min=1,max=4"`
	Source     int              `json:"source" binding:"required,min=1,max=4"`
	ReportTime time.Time        `json:"report_time"`
	Asset      IncidentAssetReq `json:"asset"`
	Metadata   IncidentMetaReq  `json:"metadata"`
}

type IncidentAssetReq struct {
	AssetName    string `json:"asset_name"`
	SystemName   string `json:"system_name"`
	DomainIP     string `json:"domain_ip"`
	SiteIP       string `json:"site_ip"`
	Unit         string `json:"unit"`
	UnitType     string `json:"unit_type"`
	Industry     string `json:"industry"`
	MLPSRecordNo string `json:"mlps_record_no"`
	MLPSLevel    string `json:"mlps_level"`
	MIITRecordNo string `json:"miit_record_no"`
	Region       string `json:"region"`
}

type IncidentMetaReq struct {
	DataNo              string    `json:"data_no"`
	IncidentType        string    `json:"incident_type"`
	IncidentURL         string    `json:"incident_url"`
	DiscoveryTime       time.Time `json:"discovery_time"`
	VendorRegion        string    `json:"vendor_region"`
	IncidentDescription string    `json:"incident_description"`
	VendorName          string    `json:"vendor_name"`
	VendorTime          time.Time `json:"vendor_time"`
	AffectedCount       string    `json:"affected_count"`
	AffectedType        string    `json:"affected_type"`
	CvssScore           float64   `json:"cvss_score"`
	CveId               string    `json:"cve_id"`
	OwaspCategory       string    `json:"owasp_category"`
	ExploitDifficulty   string    `json:"exploit_difficulty"`
	AffectScope         string    `json:"affect_scope"`
}

type IncidentUpdateReq struct {
	Name     string            `json:"name"`
	Level    *int              `json:"level"`
	Source   *int              `json:"source"`
	Asset    *IncidentAssetReq `json:"asset"`
	Metadata *IncidentMetaReq  `json:"metadata"`
}

type IncidentListReq struct {
	Name      string `form:"name"`
	AssetName string `form:"asset_name"`
	Unit      string `form:"unit"`
	Level     *int   `form:"level"`
	Status    *int   `form:"status"`
	Index     int    `form:"index"`
	Size      int    `form:"size" binding:"lte=100"`
}

type IncidentListItem struct {
	ID                  string     `json:"id"`
	IncidentNo          string     `json:"incident_no"`
	Name                string     `json:"name"`
	Level               int        `json:"level"`
	Source              int        `json:"source"`
	Status              int        `json:"status"`
	StatusText          string     `json:"status_text"`
	ReportTime          time.Time  `json:"report_time"`
	AiPreStatus         int        `json:"ai_pre_status"`
	AiOpinion           string     `json:"ai_opinion"`
	RiskScore           float64    `json:"risk_score"`
	AiTags              string     `json:"ai_tags"`
	AiCategory          string     `json:"ai_category"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	AssetName           string     `json:"asset_name"`
	Unit                string     `json:"unit"`
	RemediationDeadline *time.Time `json:"remediation_deadline"`
	RemediationAssignee string     `json:"remediation_assignee"`
	IsOverdue           bool       `json:"is_overdue"`
}

type IncidentDetailResp struct {
	model.SecurityIncident
	CurrentStep   int         `json:"current_step"`
	OperationLogs []OplogItem `json:"operation_logs"`
}

type DashboardStatsResp struct {
	Total           int64   `json:"total"`
	PendingAudit    int64   `json:"pending_audit"`
	InRemediation   int64   `json:"in_remediation"`
	Closed          int64   `json:"closed"`
	Overdue         int64   `json:"overdue"`
	TodayTotal      int64   `json:"today_total"`
	UrgentCount     int64   `json:"urgent_count"`
	DispatchCount   int64   `json:"dispatched_count"`
	RemediatingCnt  int64   `json:"remediating_count"`
	OverdueCnt      int64   `json:"overdue_count"`
	ClosedCnt       int64   `json:"closed_count"`
	RemediationRate float64 `json:"remediation_rate"`
}

type ChartTypeItem struct {
	Type       string `json:"type"`
	Count      int64  `json:"count"`
	Percentage string `json:"percentage"`
}

type ChartLevelItem struct {
	Level      int    `json:"level"`
	Label      string `json:"label"`
	Count      int64  `json:"count"`
	Percentage string `json:"percentage"`
}

type ChartTrendItem struct {
	Period  string `json:"period"`
	Date    string `json:"date"`
	Created int64  `json:"created"`
	Closed  int64  `json:"closed"`
	Pending int64  `json:"pending"`
	Count   int64  `json:"count"`
}

type OplogItem struct {
	Id              string    `json:"id"`
	IncidentId      string    `json:"incident_id"`
	IncidentNo      string    `json:"incident_no"`
	OperationType   string    `json:"operation_type"`
	OperationTypeZh string    `json:"operation_type_zh"`
	OperatorId      string    `json:"operator_id"`
	OperatorName    string    `json:"operator_name"`
	OperationTime   time.Time `json:"operation_time"`
	Result          string    `json:"result"`
	Detail          string    `json:"detail"`
	SourceSystem    string    `json:"source_system"`
	SourceSystemZh  string    `json:"source_system_zh"`
}

type OplogCallbackReq struct {
	IncidentNo    string                 `json:"incident_no" binding:"required"`
	OperationType string                 `json:"operation_type" binding:"required"`
	OperatorId    string                 `json:"operator_id"`
	OperatorName  string                 `json:"operator_name"`
	OperationTime time.Time              `json:"operation_time"`
	Result        string                 `json:"result"`
	Detail        map[string]interface{} `json:"detail"`
	CircularCode  string                 `json:"circular_code"`
}

func ToOplogItem(log model.IncidentOperationLog) OplogItem {
	return OplogItem{
		Id: log.Id, IncidentId: log.IncidentId, IncidentNo: log.IncidentNo,
		OperationType: log.OperationType, OperationTypeZh: model.IncidentOperationTypeText[log.OperationType],
		OperatorId: log.OperatorId, OperatorName: log.OperatorName,
		OperationTime: log.OperationTime, Result: log.Result, Detail: log.Detail,
		SourceSystem: log.SourceSystem, SourceSystemZh: sourceSystemZh(log.SourceSystem),
	}
}

func sourceSystemZh(s string) string {
	switch s {
	case model.IncidentSourceSystemLocal:
		return "本系统"
	case model.IncidentSourceSystemCircular:
		return "通报系统"
	default:
		return s
	}
}

func AssetReqToMap(a IncidentAssetReq) map[string]interface{} {
	m := make(map[string]interface{})
	if a.AssetName != "" {
		m["asset_name"] = a.AssetName
	}
	if a.SystemName != "" {
		m["system_name"] = a.SystemName
	}
	if a.DomainIP != "" {
		m["domain_ip"] = a.DomainIP
	}
	if a.SiteIP != "" {
		m["site_ip"] = a.SiteIP
	}
	if a.Unit != "" {
		m["unit"] = a.Unit
	}
	if a.UnitType != "" {
		m["unit_type"] = a.UnitType
	}
	if a.Industry != "" {
		m["industry"] = a.Industry
	}
	if a.MLPSRecordNo != "" {
		m["mlps_record_no"] = a.MLPSRecordNo
	}
	if a.MLPSLevel != "" {
		m["mlps_level"] = a.MLPSLevel
	}
	if a.MIITRecordNo != "" {
		m["miit_record_no"] = a.MIITRecordNo
	}
	if a.Region != "" {
		m["region"] = a.Region
	}
	return m
}

func BuildIncidentListItem(inc model.SecurityIncident, now time.Time) IncidentListItem {
	item := IncidentListItem{
		ID: inc.Id, IncidentNo: inc.IncidentNo, Name: inc.Name,
		Level: inc.Level, Source: inc.Source, Status: inc.Status,
		StatusText: model.IncidentStatusText[inc.Status],
		ReportTime: inc.ReportTime, AiPreStatus: inc.AiPreStatus,
		AiOpinion: inc.AiOpinion, RiskScore: inc.RiskScore,
		AiTags: inc.AiTags, AiCategory: inc.AiCategory,
		CreatedAt: inc.CreatedAt, UpdatedAt: inc.UpdatedAt,
		RemediationDeadline: inc.RemediationDeadline,
		RemediationAssignee: inc.RemediationAssignee,
	}
	if inc.RemediationDeadline != nil && inc.RemediationDeadline.Before(now) &&
		inc.Status != model.IncidentStatusClosed && inc.Status != model.IncidentStatusVerifying {
		item.IsOverdue = true
	}
	if inc.AssetDetail != nil {
		item.AssetName = inc.AssetDetail.AssetName
		item.Unit = inc.AssetDetail.Unit
	}
	return item
}

func GenerateIncidentNo() string {
	now := time.Now()
	return fmt.Sprintf("SI%s%04d", now.Format("20060102150405"), cryptoRandIntn(10000))
}

func cryptoRandIntn(n int) int {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return int(uint32(b[0])|uint32(b[1])<<8|uint32(b[2])<<16|uint32(b[3])<<24) % n
}
