package report

import "time"

type ReportConfig struct {
	Title       string            `json:"title"`
	Type        string            `json:"type"`
	Format      string            `json:"format"`
	TemplateID  string            `json:"template_id"`
	Filters     map[string]string `json:"filters"`
	IncludeLogo bool              `json:"include_logo"`
}

type ReportData struct {
	Title           string             `json:"title"`
	GeneratedAt     time.Time          `json:"generated_at"`
	GeneratedBy     string             `json:"generated_by"`
	Summary         ReportSummary      `json:"summary"`
	Vulnerabilities []VulnItem         `json:"vulnerabilities"`
	Assets          []AssetItem        `json:"assets"`
	Compliance      *ComplianceSection `json:"compliance,omitempty"`
	Charts          []ChartData        `json:"charts,omitempty"`
}

type ReportSummary struct {
	TotalAssets     int     `json:"total_assets"`
	TotalVulns      int     `json:"total_vulns"`
	CriticalCount   int     `json:"critical_count"`
	HighCount       int     `json:"high_count"`
	MediumCount     int     `json:"medium_count"`
	LowCount        int     `json:"low_count"`
	InfoCount       int     `json:"info_count"`
	RiskScore       float64 `json:"risk_score"`
	ComplianceScore float64 `json:"compliance_score"`
	ScanDuration    string  `json:"scan_duration"`
}

type VulnItem struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	CVEID       string `json:"cve_id"`
	Asset       string `json:"asset"`
	Status      string `json:"status"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

type AssetItem struct {
	Host         string   `json:"host"`
	IP           string   `json:"ip"`
	OpenPorts    []int    `json:"open_ports"`
	Services     []string `json:"services"`
	Fingerprints []string `json:"fingerprints"`
	VulnCount    int      `json:"vuln_count"`
}

type ComplianceSection struct {
	Framework string  `json:"framework"`
	Score     float64 `json:"score"`
	Passed    int     `json:"passed"`
	Failed    int     `json:"failed"`
	Skipped   int     `json:"skipped"`
}

type ChartData struct {
	Type  string      `json:"type"`
	Title string      `json:"title"`
	Data  interface{} `json:"data"`
}

const (
	FormatMarkdown = "markdown"
	FormatJSON     = "json"
	FormatCSV      = "csv"
	FormatSARIF    = "sarif"

	TypeExecutive  = "executive"
	TypeTechnical  = "technical"
	TypeCompliance = "compliance"
	TypeASM        = "asm"
	TypeEmergency  = "emergency"
)
