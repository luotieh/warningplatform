package compliance

import "time"

type Framework struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Standard    string `json:"standard"`
	Rules       []Rule `json:"rules"`
}

type Rule struct {
	ID          string      `json:"id"`
	FrameworkID string      `json:"framework_id"`
	Category    string      `json:"category"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Severity    string      `json:"severity"`
	CheckType   string      `json:"check_type"`
	CheckConfig CheckConfig `json:"check_config"`
	Remediation string      `json:"remediation"`
	References  []string    `json:"references"`
}

type CheckConfig struct {
	Command    string            `json:"command,omitempty"`
	FilePath   string            `json:"file_path,omitempty"`
	FileMatch  string            `json:"file_match,omitempty"`
	FilePerm   string            `json:"file_perm,omitempty"`
	Registry   string            `json:"registry,omitempty"`
	APIPath    string            `json:"api_path,omitempty"`
	Expected   string            `json:"expected"`
	Comparator string            `json:"comparator"`
	Extra      map[string]string `json:"extra,omitempty"`
}

type CheckResult struct {
	RuleID    string    `json:"rule_id"`
	TargetID  string    `json:"target_id"`
	Status    string    `json:"status"`
	Actual    string    `json:"actual"`
	Expected  string    `json:"expected"`
	Evidence  string    `json:"evidence"`
	CheckedAt time.Time `json:"checked_at"`
}

type ComplianceReport struct {
	FrameworkID  string        `json:"framework_id"`
	TargetID     string        `json:"target_id"`
	TotalRules   int           `json:"total_rules"`
	PassedRules  int           `json:"passed_rules"`
	FailedRules  int           `json:"failed_rules"`
	SkippedRules int           `json:"skipped_rules"`
	Score        float64       `json:"score"`
	Results      []CheckResult `json:"results"`
	GeneratedAt  time.Time     `json:"generated_at"`
}

const (
	StatusPass  = "pass"
	StatusFail  = "fail"
	StatusSkip  = "skip"
	StatusError = "error"

	CheckTypeCommand  = "command"
	CheckTypeFile     = "file"
	CheckTypeFilePerm = "file_perm"
	CheckTypeRegistry = "registry"
	CheckTypeAPI      = "api"

	ComparatorEqual    = "eq"
	ComparatorContains = "contains"
	ComparatorRegex    = "regex"
	ComparatorGTE      = "gte"
	ComparatorLTE      = "lte"
	ComparatorNotEmpty = "not_empty"
	ComparatorEmpty    = "empty"
)
