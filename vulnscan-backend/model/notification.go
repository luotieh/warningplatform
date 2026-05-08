package model

import "time"

type Notification struct {
	ID        string     `gorm:"primarykey;type:varchar(36)" json:"id"`
	UserID    string     `gorm:"type:varchar(64);index" json:"user_id"`
	Type      string     `gorm:"type:varchar(30);index" json:"type"`
	Title     string     `gorm:"type:varchar(500)" json:"title"`
	Content   string     `gorm:"type:text" json:"content"`
	Link      string     `gorm:"type:varchar(500)" json:"link"`
	Severity  string     `gorm:"type:varchar(20)" json:"severity"`
	Read      bool       `gorm:"default:false;index" json:"read"`
	ReadAt    *time.Time `json:"read_at"`
	TaskID    string     `gorm:"type:varchar(36);index" json:"task_id"`
	VulnID    string     `gorm:"type:varchar(36)" json:"vuln_id"`
	CreatedAt time.Time  `json:"created_at"`
}

func (Notification) TableName() string { return "vs_notification" }

const (
	NotifyTypeTaskComplete = "task_complete"
	NotifyTypeTaskFailed   = "task_failed"
	NotifyTypeVulnCritical = "vuln_critical"
	NotifyTypeVulnHigh     = "vuln_high"
	NotifyTypeScheduleRun  = "schedule_run"
	NotifyTypeIntelMatch   = "intel_match"
)

type IntelSubscription struct {
	ID          string      `gorm:"primarykey;type:varchar(36)" json:"id"`
	UserID      string      `gorm:"type:varchar(64);index" json:"user_id"`
	Name        string      `gorm:"type:varchar(200)" json:"name"`
	Products    StringArray `gorm:"type:text" json:"products"`
	Keywords    StringArray `gorm:"type:text" json:"keywords"`
	Severities  StringArray `gorm:"type:text" json:"severities"`
	OnlyExploit bool        `gorm:"default:false" json:"only_exploit"`
	OnlyKEV     bool        `gorm:"default:false" json:"only_kev"`
	Enabled     bool        `gorm:"default:true" json:"enabled"`
	LastMatchAt *time.Time  `json:"last_match_at"`
	MatchCount  int         `gorm:"default:0" json:"match_count"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

func (IntelSubscription) TableName() string { return "vs_intel_subscription" }

type IOCIndicator struct {
	ID          string      `gorm:"primarykey;type:varchar(36)" json:"id"`
	Type        string      `gorm:"type:varchar(20);index" json:"type"`
	Value       string      `gorm:"type:varchar(500);index" json:"value"`
	ThreatType  string      `gorm:"type:varchar(50)" json:"threat_type"`
	Severity    string      `gorm:"type:varchar(20);index" json:"severity"`
	Source      string      `gorm:"type:varchar(200)" json:"source"`
	Description string      `gorm:"type:text" json:"description"`
	Tags        StringArray `gorm:"type:text" json:"tags"`
	ExpiresAt   *time.Time  `json:"expires_at"`
	Enabled     bool        `gorm:"default:true;index" json:"enabled"`
	HitCount    int         `gorm:"default:0" json:"hit_count"`
	LastHitAt   *time.Time  `json:"last_hit_at"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

func (IOCIndicator) TableName() string { return "vs_ioc_indicator" }

const (
	IOCTypeIP     = "ip"
	IOCTypeDomain = "domain"
	IOCTypeHash   = "hash"
	IOCTypeURL    = "url"

	NotifyTypeIOCHit = "ioc_hit"
)
