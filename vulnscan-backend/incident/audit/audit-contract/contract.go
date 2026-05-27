package auditContract

import (
	"context"
)

type ServiceAudit interface {
	AIPreAudit(ctx context.Context, id string) (*AIPreAuditResp, error)
	ManualAudit(ctx context.Context, req ManualAuditReq) error
	AIClassify(ctx context.Context, id string) (*ClassifyResult, error)
}

type ManualAuditReq struct {
	ID          string `json:"id"`
	AuditResult string `json:"audit_result"`
	Opinion     string `json:"opinion"`
}

// ManualAuditBody 人工复核请求体（事件 ID 来自路径 :id）。
type ManualAuditBody struct {
	AuditResult string `json:"audit_result"`
	Passed      *bool  `json:"passed"`
	Opinion     string `json:"opinion"`
}

type AIPreAuditResp struct {
	AiOpinion    string          `json:"ai_opinion"`
	AiConfidence float64         `json:"ai_confidence"`
	RiskScore    float64         `json:"risk_score"`
	AiTags       string          `json:"ai_tags"`
	AiCategory   string          `json:"ai_category"`
	AiVulnDesc   string          `json:"ai_vuln_desc"`
	AiVulnHarm   string          `json:"ai_vuln_harm"`
	AiFixAdvice  string          `json:"ai_fix_advice"`
	RiskDetail   RiskScoreResult `json:"risk_detail"`
}

type RiskScoreResult struct {
	TotalScore      float64         `json:"total_score"`
	Level           string          `json:"level"`
	CvssWeight      float64         `json:"cvss_weight"`
	ExploitWeight   float64         `json:"exploit_weight"`
	ScopeWeight     float64         `json:"scope_weight"`
	LevelWeight     float64         `json:"level_weight"`
	OwaspWeight     float64         `json:"owasp_weight"`
	BreakdownItems  []RiskBreakdown `json:"breakdown_items"`
	Recommendations []string        `json:"recommendations"`
	Tags            []string        `json:"tags"`
	Category        string          `json:"category"`
}

type RiskBreakdown struct {
	Dimension string  `json:"dimension"`
	Score     float64 `json:"score"`
	MaxScore  float64 `json:"max_score"`
	Reason    string  `json:"reason"`
}

type ClassifyResult struct {
	Category       string   `json:"category"`
	SuggestedLevel int      `json:"suggested_level"`
	Tags           []string `json:"tags"`
	Confidence     float64  `json:"confidence"`
	Reasoning      string   `json:"reasoning"`
}
