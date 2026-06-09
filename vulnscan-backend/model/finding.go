package model

import "time"

type ScanFinding struct {
	ID                 string      `gorm:"primarykey;type:varchar(36)" json:"id"`
	TaskID             string      `gorm:"type:varchar(36);index;not null" json:"task_id"`
	AssetID            string      `gorm:"type:varchar(36);index" json:"asset_id"`
	ModuleID           string      `gorm:"type:varchar(50);index" json:"module_id"`
	Type               string      `gorm:"type:varchar(50);index" json:"type"`
	Category           string      `gorm:"type:varchar(20);index" json:"category"`
	Target             string      `gorm:"type:varchar(500)" json:"target"`
	Port               int         `gorm:"default:0" json:"port"`
	Protocol           string      `gorm:"type:varchar(20)" json:"protocol"`
	Title              string      `gorm:"type:varchar(500)" json:"title"`
	Description        string      `gorm:"type:text" json:"description"`
	Severity           string      `gorm:"type:varchar(20);index" json:"severity"`
	Confidence         int         `gorm:"default:0" json:"confidence"`
	ConfidenceReason   string      `gorm:"type:varchar(500)" json:"confidence_reason"`
	Evidence           string      `gorm:"type:text" json:"evidence"`
	VerificationLevel  string      `gorm:"type:varchar(20);index;default:'principle'" json:"verification_level"`
	VerificationDetail string      `gorm:"type:varchar(200)" json:"verification_detail"`
	Data               JSONMap     `gorm:"type:text" json:"data"`
	Tags               StringArray `gorm:"type:text" json:"tags"`
	CreatedAt          time.Time   `json:"created_at"`
}

func (ScanFinding) TableName() string { return "vs_scan_finding" }

const (
	FindingCategoryRecon = "recon"
	FindingCategoryVuln  = "vuln"
)

// VulnKnowledgeCache stores AI-generated vulnerability descriptions to avoid
// repeated LLM calls for the same vulnerability type.
type VulnKnowledgeCache struct {
	ID          string    `gorm:"primarykey;type:varchar(36)" json:"id"`
	VulnKey     string    `gorm:"type:varchar(500);uniqueIndex;not null" json:"vuln_key"`
	VulnType    string    `gorm:"type:varchar(50);index" json:"vuln_type"`
	Title       string    `gorm:"type:varchar(500)" json:"title"`
	CveID       string    `gorm:"type:varchar(50);index" json:"cve_id"`
	Description string    `gorm:"type:text" json:"description"`
	Cause       string    `gorm:"type:text" json:"cause"`
	Remediation string    `gorm:"type:text" json:"remediation"`
	HitCount    int       `gorm:"default:1" json:"hit_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (VulnKnowledgeCache) TableName() string { return "vs_vuln_knowledge_cache" }
