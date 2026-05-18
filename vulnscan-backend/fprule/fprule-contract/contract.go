package fpruleContract

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type FPRuleQuery struct {
	Page      int    `form:"page"`
	PageSize  int    `form:"page_size"`
	Keyword   string `form:"keyword"`
	MatchType string `form:"match_type"`
	Enabled   *bool  `form:"enabled"`
}

type MarkFPReq struct {
	FindingID string `json:"finding_id" binding:"required"`
	MatchType string `json:"match_type"`
	Reason    string `json:"reason"`
}

type ServiceFPRule interface {
	List(query FPRuleQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.FPRule, int64, error)
	GetByID(id string) (*model.FPRule, error)
	Create(item *model.FPRule) error
	Update(id string, updates map[string]any) error
	Delete(id string) error
	Toggle(id string) error
	GetActiveRules() ([]model.FPRule, error)
	IncrHitCount(ids []string) error
	MarkFromFinding(findingID, matchType, reason, userID, organizeID string) (*model.FPRule, error)
}
