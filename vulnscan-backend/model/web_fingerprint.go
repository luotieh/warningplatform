package model

type WebFingerprint struct {
	BaseModel
	Product     string `gorm:"type:varchar(128);not null;index" json:"product"`
	ProductID   string `gorm:"type:varchar(36);index" json:"product_id"`
	Category    string `gorm:"type:varchar(64);not null;index" json:"category"`
	Version     string `gorm:"type:varchar(64)" json:"version"`
	Description string `gorm:"type:text" json:"description"`
	Priority    int    `gorm:"default:50" json:"priority"`
	Status      string `gorm:"type:varchar(16);default:'active'" json:"status"`
	Source      string `gorm:"type:varchar(64);default:'custom'" json:"source"`

	// header 匹配规则: JSON object {"Server": "nginx", "X-Powered-By": "PHP"}
	HeaderRules string `gorm:"type:text" json:"header_rules"`
	// body 匹配规则: JSON array ["wp-content", "wp-includes"]
	BodyRules string `gorm:"type:text" json:"body_rules"`
	// favicon MD5 哈希
	FaviconHash string `gorm:"type:varchar(64)" json:"favicon_hash"`
	// meta 标签匹配: JSON object {"generator": "WordPress"}
	MetaRules string `gorm:"type:text" json:"meta_rules"`
	// 版本提取正则
	VersionExpr string `gorm:"type:text" json:"version_expr"`
}

func (WebFingerprint) TableName() string { return "vs_web_fingerprint" }
