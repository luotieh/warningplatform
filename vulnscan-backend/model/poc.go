package model

import "time"

// PocTemplate stores Nuclei-compatible PoC definitions in the database.
type PocTemplate struct {
	ID          string      `gorm:"primarykey;type:varchar(36)" json:"id"`
	PocID       string      `gorm:"type:varchar(200);uniqueIndex;not null" json:"poc_id"`
	Name        string      `gorm:"type:varchar(500);not null" json:"name"`
	Author      string      `gorm:"type:varchar(200)" json:"author"`
	Severity    string      `gorm:"type:varchar(20);index" json:"severity"`
	Description string      `gorm:"type:text" json:"description"`
	Reference   StringArray `gorm:"type:text" json:"reference"`
	Tags        StringArray `gorm:"type:text" json:"tags"`
	Category    string      `gorm:"type:varchar(100);index" json:"category"`

	Content string `gorm:"type:text;not null" json:"content"`
	Format  string `gorm:"type:varchar(20);default:'yaml'" json:"format"`
	Version string `gorm:"type:varchar(20)" json:"version"`

	CVE  string `gorm:"type:varchar(50);index" json:"cve"`
	CWE  string `gorm:"type:varchar(50)" json:"cwe"`
	CVSS string `gorm:"type:varchar(20)" json:"cvss"`

	// 结构化产品匹配字段
	Product       string `gorm:"type:varchar(200);index" json:"product"`
	Vendor        string `gorm:"type:varchar(200);index" json:"vendor"`
	AffectedRange string `gorm:"type:varchar(200)" json:"affected_range"`
	CPE           string `gorm:"type:varchar(300)" json:"cpe"`
	ProductID     string `gorm:"type:varchar(36);index" json:"product_id"`

	Enabled  bool  `gorm:"default:true;index" json:"enabled"`
	Builtin  bool  `gorm:"default:false" json:"builtin"`
	Verified bool  `gorm:"default:false" json:"verified"`
	HitCount int64 `gorm:"default:0" json:"hit_count"`

	Source      string    `gorm:"type:varchar(100)" json:"source"`
	SourceURL   string    `gorm:"type:varchar(500)" json:"source_url"`
	SyncVersion int64     `gorm:"index;default:0" json:"sync_version"`
	SourceType  string    `gorm:"type:varchar(20);default:'local'" json:"source_type"`
	AuthorID    string    `gorm:"type:varchar(64)" json:"author_id"`
	OrganizeID  string    `gorm:"type:varchar(64);index" json:"organize_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (PocTemplate) TableName() string { return "vs_poc_template" }
