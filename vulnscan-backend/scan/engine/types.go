package engine

import (
	"context"
	"time"
)

type Target struct {
	Host     string            `json:"host"`
	IP       string            `json:"ip"`
	Port     int               `json:"port"`
	Protocol string            `json:"protocol"`
	URL      string            `json:"url"`
	Extra    map[string]string `json:"extra,omitempty"`
}

type VerificationLevel string

const (
	VerifyPrinciple VerificationLevel = "principle" // 原理验证
	VerifyExploit   VerificationLevel = "exploit"   // 实际利用
)

type Finding struct {
	ModuleID           string            `json:"module_id"`
	Target             *Target           `json:"target"`
	Type               string            `json:"type"`
	Title              string            `json:"title"`
	Description        string            `json:"description"`
	Severity           string            `json:"severity"`
	Confidence         int               `json:"confidence"`
	ConfidenceReason   string            `json:"confidence_reason,omitempty"`
	Evidence           string            `json:"evidence"`
	Data               map[string]string `json:"data,omitempty"`
	Timestamp          time.Time         `json:"timestamp"`
	CVEIDs             []string          `json:"cve_ids,omitempty"`
	CWEIDs             []string          `json:"cwe_ids,omitempty"`
	CVSSScore          float64           `json:"cvss_score,omitempty"`
	Remediation        string            `json:"remediation,omitempty"`
	VerificationLevel  VerificationLevel `json:"verification_level,omitempty"`
	VerificationDetail string            `json:"verification_detail,omitempty"`
}

type ModuleResult struct {
	ModuleID string        `json:"module_id"`
	Targets  []*Target     `json:"targets,omitempty"`
	Findings []*Finding    `json:"findings,omitempty"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}

type ScanModule interface {
	ID() string
	Name() string
	Category() string
	Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error)
}

type ModuleRegistry struct {
	modules map[string]ScanModule
}

func NewModuleRegistry() *ModuleRegistry {
	return &ModuleRegistry{modules: make(map[string]ScanModule)}
}

func (r *ModuleRegistry) Register(m ScanModule) {
	r.modules[m.ID()] = m
}

func (r *ModuleRegistry) Get(id string) (ScanModule, bool) {
	m, ok := r.modules[id]
	return m, ok
}

func (r *ModuleRegistry) List() []ScanModule {
	list := make([]ScanModule, 0, len(r.modules))
	for _, m := range r.modules {
		list = append(list, m)
	}
	return list
}
