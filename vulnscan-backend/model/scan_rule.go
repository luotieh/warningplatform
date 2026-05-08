package model

const (
	RuleTypeJSAnalyze  = "js_analyze"
	RuleTypeWAFDetect  = "waf_detect"
	RuleTypeTechDetect = "tech_detect"

	RuleStatusActive   = "active"
	RuleStatusDisabled = "disabled"
	RuleStatusDraft    = "draft"

	MatchLocationHeader = "header"
	MatchLocationBody   = "body"
	MatchLocationCookie = "cookie"
	MatchLocationMeta   = "meta"
	MatchLocationScript = "script"
	MatchLocationURL    = "url"
)

// ScanRule 通用扫描规则 — JS分析/WAF检测/技术栈检测共用
type ScanRule struct {
	BaseModel
	RuleType    string `gorm:"type:varchar(32);not null;index" json:"rule_type"`
	Name        string `gorm:"type:varchar(128);not null" json:"name"`
	Category    string `gorm:"type:varchar(64);not null;index" json:"category"`
	Description string `gorm:"type:text" json:"description"`
	Severity    string `gorm:"type:varchar(16);default:'info'" json:"severity"`
	Confidence  int    `gorm:"default:80" json:"confidence"`
	Status      string `gorm:"type:varchar(16);default:'active'" json:"status"`
	Priority    int    `gorm:"default:50" json:"priority"`
	Source      string `gorm:"type:varchar(64);default:'builtin'" json:"source"`

	// 匹配规则
	MatchLocation string `gorm:"type:varchar(32);not null" json:"match_location"`
	MatchKey      string `gorm:"type:varchar(128)" json:"match_key"`
	MatchPattern  string `gorm:"type:text;not null" json:"match_pattern"`
	MatchType     string `gorm:"type:varchar(16);default:'regex'" json:"match_type"`

	// 版本提取（仅 tech_detect 使用）
	VersionPattern string `gorm:"type:text" json:"version_pattern"`

	// 隐含推导（仅 tech_detect 使用）
	Implies StringArray `gorm:"type:text" json:"implies"`

	// WAF 特有：主动触发 payload 列表
	Payloads StringArray `gorm:"type:text" json:"payloads"`

	// 扩展元数据
	Metadata JSONMap `gorm:"type:text" json:"metadata"`

	SyncVersion int64  `gorm:"index;default:0" json:"sync_version"`
	SourceType  string `gorm:"type:varchar(20);default:'local'" json:"source_type"`
}

func (ScanRule) TableName() string { return "vs_scan_rule" }
