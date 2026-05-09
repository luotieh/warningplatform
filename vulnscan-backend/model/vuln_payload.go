package model

import (
	"time"

	"gorm.io/gorm"
)

// VulnPayload 漏洞扫描 Payload 存储模型
// 用于统一管理 SQLi、XSS、CRLF 等各类漏洞检测的 payload
// 支持通过管理界面动态增删改，扫描时从数据库加载
type VulnPayload struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	Category    string         `gorm:"type:varchar(50);not null;index:idx_category" json:"category"` // sqli, xss, crlf, host_header, ssrf, cmdi, lfi, ssti, xxe, etc.
	Name        string         `gorm:"type:varchar(200);not null" json:"name"`                       // payload 名称
	Value       string         `gorm:"type:text;not null" json:"value"`                              // payload 值
	Type        string         `gorm:"type:varchar(50)" json:"type"`                                 // error, time, boolean, union, reflected, stored, etc.
	Databases   string         `gorm:"type:varchar(500)" json:"databases"`                           // 适用数据库（逗号分隔）：mysql,postgresql,mssql,oracle,all
	Expect      string         `gorm:"type:text" json:"expect"`                                      // 期望匹配内容（用于 XSS 等反射型检测）
	Context     string         `gorm:"type:varchar(100)" json:"context"`                             // 上下文类型：html, attribute, js, url, etc.
	Tags        string         `gorm:"type:varchar(500)" json:"tags"`                                // 标签（逗号分隔）：basic, quote, union, blind, etc.
	Severity    string         `gorm:"type:varchar(20)" json:"severity"`                             // 漏洞严重等级
	Description string         `gorm:"type:text" json:"description"`                                 // payload 说明
	Enabled     bool           `gorm:"default:true;index" json:"enabled"`                            // 是否启用
	SortOrder   int            `gorm:"default:0" json:"sort_order"`                                  // 排序顺序
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

func (VulnPayload) TableName() string { return "vuln_payloads" }

// VulnPayloadPattern 漏洞检测模式/规则
// 用于存储错误匹配正则、敏感数据正则、DOM sink/source 等检测规则
type VulnPayloadPattern struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	Category    string         `gorm:"type:varchar(50);not null;index:idx_pattern_category" json:"category"` // sqli_error, sensitive_data, dom_sink, dom_source, etc.
	Name        string         `gorm:"type:varchar(200);not null" json:"name"`
	Pattern     string         `gorm:"type:text;not null" json:"pattern"` // 正则表达式或匹配模式
	Description string         `gorm:"type:text" json:"description"`
	Severity    string         `gorm:"type:varchar(20)" json:"severity"`
	Enabled     bool           `gorm:"default:true;index" json:"enabled"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

func (VulnPayloadPattern) TableName() string { return "vuln_payload_patterns" }

// VulnPayloadConfig 漏洞扫描配置（如 boolean 配对、路径列表等）
type VulnPayloadConfig struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Category  string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_config_category_key" json:"category"` // sqli_boolean, session_fix_paths, smuggling_headers, etc.
	ConfigKey string    `gorm:"type:varchar(200);not null;uniqueIndex:idx_config_category_key" json:"config_key"`
	ConfigVal string    `gorm:"type:text" json:"config_val"` // JSON 格式存储复杂配置
	Enabled   bool      `gorm:"default:true" json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (VulnPayloadConfig) TableName() string { return "vuln_payload_configs" }
