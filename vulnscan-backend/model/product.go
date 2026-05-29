package model

// Product 产品知识库 — 统一的产品实体，关联 PoC、指纹、漏洞
type Product struct {
	BaseModel
	Name        string      `gorm:"type:varchar(200);uniqueIndex;not null" json:"name"`
	Vendor      string      `gorm:"type:varchar(200);index" json:"vendor"`
	Category    string      `gorm:"type:varchar(100);index" json:"category"`
	Description string      `gorm:"type:text" json:"description"`
	Homepage    string      `gorm:"type:varchar(500)" json:"homepage"`
	LogoURL     string      `gorm:"type:varchar(500)" json:"logo_url"`
	CPEPrefix   string      `gorm:"type:varchar(300);index" json:"cpe_prefix"`
	Tags        StringArray `gorm:"type:text" json:"tags"`
	Aliases     StringArray `gorm:"type:text" json:"aliases"`
}

func (Product) TableName() string { return "vs_product" }
