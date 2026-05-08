package vulnContract

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type VulnQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Severity string `form:"severity"`
	Status   string `form:"status"`
	TaskID   string `form:"task_id"`
	AssetID  string `form:"asset_id"`
	Category string `form:"category"`
}

type VulnStats struct {
	Total    int64 `json:"total"`
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Info     int64 `json:"info"`
	Open     int64 `json:"open"`
	Fixed    int64 `json:"fixed"`
	Ignored  int64 `json:"ignored"`
}

type ServiceVuln interface {
	List(query VulnQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Vulnerability, int64, error)
	GetByID(id string) (*model.Vulnerability, error)
	Create(item *model.Vulnerability) error
	BatchCreate(items []*model.Vulnerability) (int, error)
	Update(id string, updates map[string]any) error
	Delete(id string) error
	MarkFixed(id string) error
	MarkIgnored(id string, reason string) error
	Reopen(id string) error
	Stats(scopes ...func(*gorm.DB) *gorm.DB) (*VulnStats, error)
	GetStatusHistory(vulnID string) ([]model.VulnStatusHistory, error)
}
