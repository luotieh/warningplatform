package statsContract

import (
	"context"

	coreContract "vulnscan-backend/incident/core/core-contract"
)

type ServiceStats interface {
	GetRemediationStats(ctx context.Context) (*RemediationStatsResp, error)
	GetOverdueList(ctx context.Context, req OverdueListReq) ([]coreContract.IncidentListItem, int64, error)
	GetMultiDimAnalysis(ctx context.Context, dimension string) ([]MultiDimItem, error)
	GenerateReport(ctx context.Context, req ReportReq) ([]byte, string, error)
	ExportBatch(ctx context.Context, ids []string, format string) ([]byte, string, error)
	ExportSingle(ctx context.Context, id string, format string) ([]byte, string, error)
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
	Index int `form:"index"`
	Size  int `form:"size" binding:"lte=100"`
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
	Keyword string `form:"keyword"`
	Index   int    `form:"index"`
	Size    int    `form:"size" binding:"lte=100"`
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
