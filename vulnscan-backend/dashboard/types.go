package dashboard

import "time"

type MetricQuery struct {
	MetricName string            `json:"metric_name"`
	Filters    map[string]string `json:"filters"`
	GroupBy    string            `json:"group_by"`
	TimeRange  TimeRange         `json:"time_range"`
	Interval   string            `json:"interval"`
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type MetricResult struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Points []DataPoint       `json:"points"`
	Total  float64           `json:"total"`
}

type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

type DashboardConfig struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Widgets []Widget `json:"widgets"`
}

type Widget struct {
	ID     string      `json:"id"`
	Type   string      `json:"type"`
	Title  string      `json:"title"`
	X      int         `json:"x"`
	Y      int         `json:"y"`
	Width  int         `json:"width"`
	Height int         `json:"height"`
	Query  MetricQuery `json:"query"`
}

type SecurityPosture struct {
	TotalAssets     int            `json:"total_assets"`
	TotalVulns      int            `json:"total_vulns"`
	RiskScore       float64        `json:"risk_score"`
	ComplianceScore float64        `json:"compliance_score"`
	SeverityDist    map[string]int `json:"severity_distribution"`
	VulnTrend       []DataPoint    `json:"vuln_trend"`
	TopVulnAssets   []AssetRisk    `json:"top_vuln_assets"`
	ActiveScans     int            `json:"active_scans"`
	WorkerStatus    map[string]int `json:"worker_status"`
	MonitorStats    MonitorStats   `json:"monitor_stats"`
	TopRiskAssets   []TopRiskAsset `json:"top_risk_assets"`
}

type MonitorStats struct {
	TotalTasks   int `json:"total_tasks"`
	EnabledTasks int `json:"enabled_tasks"`
	TotalAlerts  int `json:"total_alerts"`
	OpenAlerts   int `json:"open_alerts"`
}

type TopRiskAsset struct {
	AssetID    string  `json:"asset_id"`
	Name       string  `json:"name"`
	Address    string  `json:"address"`
	RiskScore  float64 `json:"risk_score"`
	VulnCount  int     `json:"vuln_count"`
	AlertCount int     `json:"alert_count"`
}

type AssetRisk struct {
	Host      string `json:"host"`
	VulnCount int    `json:"vuln_count"`
	RiskScore int    `json:"risk_score"`
}

type ScanProgress struct {
	TaskID        string    `json:"task_id"`
	TaskName      string    `json:"task_name"`
	Status        string    `json:"status"`
	Progress      float64   `json:"progress"`
	Stage         string    `json:"stage"`
	StartedAt     time.Time `json:"started_at"`
	TargetsTotal  int       `json:"targets_total"`
	TargetsDone   int       `json:"targets_done"`
	FindingsCount int       `json:"findings_count"`
}
