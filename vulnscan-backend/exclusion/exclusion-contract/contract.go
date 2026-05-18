package exclusionContract

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type ExclusionQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	RuleType string `form:"rule_type"`
	Scope    string `form:"scope"`
	Enabled  *bool  `form:"enabled"`
}

type ServiceExclusion interface {
	List(query ExclusionQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.ScanExclusion, int64, error)
	GetByID(id string) (*model.ScanExclusion, error)
	Create(item *model.ScanExclusion) error
	Update(id string, updates map[string]any) error
	Delete(id string) error
	Toggle(id string) error
	GetActiveRules(scopes ...string) ([]model.ScanExclusion, error)
	IncrHitCount(ids []string) error
}
