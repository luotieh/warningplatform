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
	Title             string             `json:"title"`
	GeneratedAt       time.Time          `json:"generated_at"`
	GeneratedBy       string             `json:"generated_by"`
	Task              *ReportTaskMeta    `json:"task,omitempty"`
	Summary           ReportSummary      `json:"summary"`
	Vulnerabilities   []VulnItem         `json:"vulnerabilities"`
	DiscoveryFindings []DiscoveryItem    `json:"discovery_findings"`
	DiscoveryGroups   []DiscoveryGroup   `json:"discovery_groups,omitempty"`
	Assets            []AssetItem        `json:"assets"`
	Products          []ProductSection   `json:"products,omitempty"`
	Compliance        *ComplianceSection `json:"compliance,omitempty"`
	Charts            []ChartData        `json:"charts,omitempty"`
}

type ReportTaskMeta struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	Targets    []string   `json:"targets,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type ReportSummary struct {
	TotalAssets        int     `json:"total_assets"`
	TotalFindings      int     `json:"total_findings"`
	TotalVulns         int     `json:"total_vulns"`
	DiscoveryCount     int     `json:"discovery_count"`
	TotalDiscoveryType int     `json:"total_discovery_types"`
	CriticalCount      int     `json:"critical_count"`
	HighCount          int     `json:"high_count"`
	MediumCount        int     `json:"medium_count"`
	LowCount           int     `json:"low_count"`
	InfoCount          int     `json:"info_count"`
	RiskScore          float64 `json:"risk_score"`
	ComplianceScore    float64 `json:"compliance_score"`
	ScanDuration       string  `json:"scan_duration"`
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
	ProductID   string `json:"product_id,omitempty"`
	ProductName string `json:"product_name,omitempty"`
}

type ProductSection struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Vendor      string `json:"vendor"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Homepage    string `json:"homepage"`
	VulnCount   int    `json:"vuln_count"`
	PocCount    int    `json:"poc_count"`
}

type DiscoveryItem struct {
	ID          string    `json:"id"`
	Category    string    `json:"category"`
	Type        string    `json:"type"`
	TypeLabel   string    `json:"type_label"`
	Title       string    `json:"title"`
	Target      string    `json:"target"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	Severity    string    `json:"severity"`
	Confidence  int       `json:"confidence"`
	ModuleID    string    `json:"module_id"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	Summary     string    `json:"summary"`
	CreatedAt   time.Time `json:"created_at"`
}

type DiscoveryGroup struct {
	Type  string `json:"type"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

type AssetItem struct {
	Host         string   `json:"host"`
	IP           string   `json:"ip"`
	OpenPorts    []int    `json:"open_ports"`
	Services     []string `json:"services"`
	Fingerprints []string `json:"fingerprints"`
	VulnCount    int      `json:"vuln_count"`
	FindingCount int      `json:"finding_count"`
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
	FormatWord     = "word"
	FormatPDF      = "pdf"
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
