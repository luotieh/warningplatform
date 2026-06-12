package taskContract

import (
	"context"
	"vulnscan-backend/model"

	"code.yt-security.com/public/access/ai"
	"gorm.io/gorm"
)

type AIEnrichResult struct {
	Description string `json:"description"`
	Cause       string `json:"cause"`
	Remediation string `json:"remediation"`
}

type TaskQuery struct {
	Page         int    `form:"page"`
	PageSize     int    `form:"page_size"`
	Keyword      string `form:"keyword"`
	Status       string `form:"status"`
	Type         string `form:"type"`
	ExcludeTypes string `form:"exclude_types"`
	TemplateID   string `form:"template_id"`
}

type CreateTaskReq struct {
	Name       string        `json:"name" binding:"required"`
	TemplateID string        `json:"template_id"`
	Type       string        `json:"type"`
	Targets    []string      `json:"targets" binding:"required"`
	Config     model.JSONMap `json:"config"`
	Parameters model.JSONMap `json:"parameters"`
	Priority   int           `json:"priority"`
}

type FindingQuery struct {
	TaskID      string `form:"-"`
	Page        int    `form:"page"`
	PageSize    int    `form:"page_size"`
	Category    string `form:"category"`
	Type        string `form:"type"`
	ExcludeType string `form:"exclude_type"`
	Severity    string `form:"severity"`
	ModuleID    string `form:"module_id"`
	Keyword     string `form:"keyword"`
	Target      string `form:"target"`
}

type FindingSummary struct {
	TotalFindings int            `json:"total_findings"`
	ByCategory    map[string]int `json:"by_category"`
	ByType        map[string]int `json:"by_type"`
	BySeverity    map[string]int `json:"by_severity"`
	ByModule      map[string]int `json:"by_module"`
}

type AssetSummary struct {
	Target     string         `json:"target"`
	IP         string         `json:"ip"`
	Ports      []AssetPort    `json:"ports"`
	Services   []string       `json:"services"`
	Techs      []string       `json:"techs"`
	Banner     string         `json:"banner"`
	Title      string         `json:"title"`
	StatusCode int            `json:"status_code"`
	WAF        string         `json:"waf"`
	OS         string         `json:"os"`
	VulnCount  map[string]int `json:"vuln_count"`
	FindingIDs []string       `json:"finding_ids"`
	FirstSeen  string         `json:"first_seen"`
}

type AssetPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Banner   string `json:"banner"`
}

type EvidenceReportData struct {
	FindingID     string `json:"finding_id"`
	Title         string `json:"title"`
	Severity      string `json:"severity"`
	Target        string `json:"target"`
	Port          int    `json:"port"`
	VulnType      string `json:"vuln_type"`
	Description   string `json:"description"`
	Confidence    int    `json:"confidence"`
	ConfReason    string `json:"confidence_reason"`
	VerifyLevel   string `json:"verification_level"`
	VerifyDetail  string `json:"verification_detail"`
	Evidence      string `json:"evidence"`
	Payload       string `json:"payload,omitempty"`
	MatchedAt     string `json:"matched_at,omitempty"`
	Request       string `json:"request,omitempty"`
	Response      string `json:"response,omitempty"`
	CurlCommand   string `json:"curl_command,omitempty"`
	Screenshot    string `json:"screenshot,omitempty"`
	CveID         string `json:"cve_id,omitempty"`
	CvssScore     string `json:"cvss_score,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	CreatedAt     string `json:"created_at"`
	AIVerified    bool   `json:"ai_verified"`
	AIReasoning   string `json:"ai_reasoning,omitempty"`
	AISuggestion  string `json:"ai_suggestion,omitempty"`
	AIFalseReason string `json:"ai_false_reason,omitempty"`
}

type ServiceTask interface {
	List(query TaskQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.ScanTask, int64, error)
	GetByID(id string) (*model.ScanTask, error)
	Create(item *model.ScanTask) error
	Update(id string, updates map[string]any) error
	Delete(id string) error
	Cancel(id string) error
	Pause(id string) error
	Resume(id string) error
	ListFindings(query FindingQuery) ([]model.ScanFinding, int64, error)
	FindingSummary(taskID string) (*FindingSummary, error)
	ListAssets(taskID string) ([]AssetSummary, error)
	ListLogs(taskID string, limit int) ([]model.ScanLog, error)
	AIEnrichFinding(ctx context.Context, findingID string, chatSvc ai.Service) (*AIEnrichResult, error)
	GetEvidenceReport(findingID string) (*EvidenceReportData, error)
	DB() *gorm.DB
}
