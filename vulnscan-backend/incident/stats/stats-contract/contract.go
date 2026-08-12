package statsContract

import (
	"context"
	"time"

	coreContract "vulnscan-backend/incident/core/core-contract"
)

// IncidentReportData 对齐「网络安全隐患详情」通报表字段。
type IncidentReportData struct {
	Title               string                            `json:"title"`
	GeneratedAt         time.Time                         `json:"generated_at"`
	IncidentNo          string                            `json:"incident_no"`
	DataNo              string                            `json:"data_no"`
	Name                string                            `json:"name"`
	VendorRegion        string                            `json:"vendor_region"`
	IncidentURL         string                            `json:"incident_url"`
	AssetName           string                            `json:"asset_name"`
	SystemName          string                            `json:"system_name"`
	DomainIP            string                            `json:"domain_ip"`
	SiteIP              string                            `json:"site_ip"`
	Region              string                            `json:"region"`
	IncidentType        string                            `json:"incident_type"`
	WarningLevel        string                            `json:"warning_level"`
	Level               string                            `json:"level"`
	DiscoveryTime       string                            `json:"discovery_time"`
	VendorName          string                            `json:"vendor_name"`
	VendorTime          string                            `json:"vendor_time"`
	AffectedCount       string                            `json:"affected_count"`
	AffectedType        string                            `json:"affected_type"`
	Unit                string                            `json:"unit"`
	UnitType            string                            `json:"unit_type"`
	Industry            string                            `json:"industry"`
	MIITRecordNo        string                            `json:"miit_record_no"`
	MLPSLevel           string                            `json:"mlps_level"`
	MLPSRecordNo        string                            `json:"mlps_record_no"`
	Description         string                            `json:"description"`
	DescriptionSections IncidentReportDescriptionSections `json:"description_sections"`
	EvidenceImages      []IncidentReportEvidenceImage     `json:"evidence_images,omitempty"`
	Attachment          string                            `json:"attachment"`
	Source              string                            `json:"source"`
	Status              string                            `json:"status"`
	RiskScore           float64                           `json:"risk_score"`
	AiOpinion           string                            `json:"ai_opinion"`
	AiTags              string                            `json:"ai_tags"`
	ReportTime          string                            `json:"report_time"`
	CveID               string                            `json:"cve_id"`
	CvssScore           float64                           `json:"cvss_score"`
	RemediationPlan     string                            `json:"remediation_plan"`
	RemediationResult   string                            `json:"remediation_result"`
	RemediationAdvice   string                            `json:"remediation_advice"`
	Assignee            string                            `json:"remediation_assignee"`
	Deadline            string                            `json:"remediation_deadline"`
	OperationLogs       []IncidentReportOplog             `json:"operation_logs"`
	Vulnerabilities     []IncidentReportVuln              `json:"vulnerabilities"`
	// 安全事件分析报告扩展字段（对齐 docs/security_incident_report_template.md）。
	CoreConclusion   string                          `json:"core_conclusion,omitempty"`
	LevelEmoji       string                          `json:"level_emoji,omitempty"`
	LevelBasis       string                          `json:"level_basis,omitempty"`
	NotifyTargets    string                          `json:"notify_targets,omitempty"`
	AssetIPRange     string                          `json:"asset_ip_range,omitempty"`
	TrafficEvidence  []IncidentReportTrafficEvidence `json:"traffic_evidence,omitempty"`
	Iocs             []IncidentReportIoc             `json:"iocs,omitempty"`
	IocValidity      string                          `json:"ioc_validity,omitempty"`
	Impact           IncidentReportImpact            `json:"impact,omitempty"`
	ImmediateActions []IncidentReportAction          `json:"immediate_actions,omitempty"`
	FollowupActions  []IncidentReportAction          `json:"followup_actions,omitempty"`
	Attachments      []IncidentReportAttachment      `json:"attachments,omitempty"`
}

// IncidentReportDescriptionSections 隐患描述分段（成因/证据/详细证据/溯源）。
type IncidentReportDescriptionSections struct {
	HasSections bool   `json:"has_sections"`
	Cause       string `json:"cause,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Trace       string `json:"trace,omitempty"`
}

// IncidentReportEvidenceImage Word/PDF 嵌入的监测证据图。
type IncidentReportEvidenceImage struct {
	Caption  string `json:"caption"`
	MIMEType string `json:"mime_type"`
	Base64   string `json:"base64,omitempty"`
}

type IncidentReportOplog struct {
	Operation string `json:"operation"`
	Operator  string `json:"operator"`
	Time      string `json:"time"`
	Comment   string `json:"comment"`
}

type IncidentReportVuln struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	CVEID       string `json:"cve_id"`
	Asset       string `json:"asset"`
	Status      string `json:"status"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// IncidentReportTrafficEvidence 关键流量证据（数字来自确定性量化引擎）。
type IncidentReportTrafficEvidence struct {
	Type           string `json:"type"`
	Detail         string `json:"detail"`
	Source         string `json:"source"`
	Confidence     int    `json:"confidence"`
	ConfidenceText string `json:"confidence_text"`
}

type IncidentReportIoc struct {
	Type         string `json:"type"`
	Value        string `json:"value"`
	ThreatSource string `json:"threat_source"`
	Match        string `json:"match"`
}

type IncidentReportImpact struct {
	Business string `json:"business"`
	DataRisk string `json:"data_risk"`
	Intent   string `json:"intent"`
}

type IncidentReportAction struct {
	Action string `json:"action"`
	Detail string `json:"detail"`
}

type IncidentReportAttachment struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type ServiceStats interface {
	GetRemediationStats(ctx context.Context) (*RemediationStatsResp, error)
	GetOverdueList(ctx context.Context, req OverdueListReq) ([]coreContract.IncidentListItem, int64, error)
	GetMultiDimAnalysis(ctx context.Context, dimension string) ([]MultiDimItem, error)
	GenerateReport(ctx context.Context, req ReportReq) ([]byte, string, error)
	ExportBatch(ctx context.Context, ids []string, format string) ([]byte, string, error)
	ExportSingle(ctx context.Context, id string, format string) ([]byte, string, error)
	PreviewIncidentReport(ctx context.Context, id string) (*IncidentReportData, error)
	ExportIncidentReport(ctx context.Context, id string, format string) ([]byte, string, error)
	GetTrendPrediction(ctx context.Context, rangeType string, predictDays int) (*TrendPrediction, error)
	GetAIAnalysis(ctx context.Context) (*AIAnalysisSummary, error)
	GetAssetProfile(ctx context.Context, req AssetProfileReq) (*AssetProfileResp, error)
	ListAssetSummary(ctx context.Context, req AssetListReq) ([]AssetSummaryItem, int64, error)
}

type RemediationStatsResp struct {
	TotalCount        int64   `json:"total_count"`
	RemediatedCount   int64   `json:"remediated_count"`
	OverdueCount      int64   `json:"overdue_count"`
	RemediationRate   float64 `json:"remediation_rate"`
	OverdueRate       float64 `json:"overdue_rate"`
	AvgRemediationDay float64 `json:"avg_remediation_day"`
	ClosedCount       int64   `json:"closed_count"`
	VerifyingCount    int64   `json:"verifying_count"`
}

type OverdueListReq struct {
	Page     int `form:"page"`
	PageSize int `form:"page_size" binding:"lte=100"`
}

type MultiDimItem struct {
	Dimension string `json:"dimension"`
	Value     string `json:"value"`
	Count     int64  `json:"count"`
}

type ReportReq struct {
	Period string `form:"period" binding:"required,oneof=month quarter"`
	Year   int    `form:"year"`
	Value  int    `form:"value"`
	Format string `form:"format"`
}

type TrendPrediction struct {
	Historical []TrendPoint `json:"historical"`
	Predicted  []TrendPoint `json:"predicted"`
	Algorithm  string       `json:"algorithm"`
	Confidence float64      `json:"confidence"`
}

type TrendPoint struct {
	Date  string  `json:"date"`
	Count float64 `json:"count"`
}

type AIAnalysisSummary struct {
	OverallRisk     string        `json:"overall_risk"`
	RiskScore       float64       `json:"risk_score"`
	Summary         string        `json:"summary"`
	TopRiskAreas    []string      `json:"top_risk_areas"`
	TrendDirection  string        `json:"trend_direction"`
	Recommendations []string      `json:"recommendations"`
	HotCategories   []HotCategory `json:"hot_categories"`
}

type HotCategory struct {
	Name  string  `json:"name"`
	Count int64   `json:"count"`
	Ratio float64 `json:"ratio"`
}

type AssetProfileReq struct {
	AssetName string `form:"asset_name"`
	DomainIP  string `form:"domain_ip"`
	Unit      string `form:"unit"`
}

type AssetProfileResp struct {
	AssetName       string                          `json:"asset_name"`
	SystemName      string                          `json:"system_name"`
	DomainIP        string                          `json:"domain_ip"`
	Unit            string                          `json:"unit"`
	Industry        string                          `json:"industry"`
	MLPSLevel       string                          `json:"mlps_level"`
	Region          string                          `json:"region"`
	TotalIncidents  int64                           `json:"total_incidents"`
	OpenIncidents   int64                           `json:"open_incidents"`
	ClosedIncidents int64                           `json:"closed_incidents"`
	OverdueCount    int64                           `json:"overdue_count"`
	LevelDistro     []coreContract.ChartLevelItem   `json:"level_distribution"`
	RecentIncidents []coreContract.IncidentListItem `json:"recent_incidents"`
	RiskScore       float64                         `json:"risk_score"`
	Timeline        []AssetTimelineItem             `json:"timeline"`
}

type AssetTimelineItem struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

type AssetListReq struct {
	Keyword  string `form:"keyword"`
	Page     int    `form:"page"`
	PageSize int    `form:"page_size" binding:"lte=100"`
}

type AssetSummaryItem struct {
	AssetDetailID string  `json:"asset_detail_id"`
	AssetName     string  `json:"asset_name"`
	SystemName    string  `json:"system_name"`
	DomainIP      string  `json:"domain_ip"`
	Unit          string  `json:"unit"`
	IncidentCount int64   `json:"incident_count"`
	AvgRiskScore  float64 `json:"avg_risk_score"`
}
