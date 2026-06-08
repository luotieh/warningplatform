package scanrunner

import (
	"gorm.io/gorm"

	serulestore "code.yt-security.com/public/scanengine/rulestore"

	"vulnscan-backend/model"
)

// RuleStoreDataSourceAdapter implements scanengine/rulestore.DataSource using gorm DB.
type RuleStoreDataSourceAdapter struct {
	db *gorm.DB
}

func NewRuleStoreDataSourceAdapter(db *gorm.DB) serulestore.DataSource {
	return &RuleStoreDataSourceAdapter{db: db}
}

func (a *RuleStoreDataSourceAdapter) GetRules() []serulestore.Rule {
	if a.db == nil {
		return nil
	}
	var dbRules []model.ScanRule
	a.db.Where("status = ?", "active").Find(&dbRules)

	rules := make([]serulestore.Rule, 0, len(dbRules))
	for _, r := range dbRules {
		rules = append(rules, serulestore.Rule{
			ID:             r.ID,
			RuleType:       r.RuleType,
			Name:           r.Name,
			Category:       r.Category,
			Description:    r.Description,
			Severity:       r.Severity,
			Confidence:     r.Confidence,
			Status:         r.Status,
			Priority:       r.Priority,
			Source:         r.Source,
			MatchLocation:  r.MatchLocation,
			MatchKey:       r.MatchKey,
			MatchPattern:   r.MatchPattern,
			MatchType:      r.MatchType,
			VersionPattern: r.VersionPattern,
			Implies:        []string(r.Implies),
			Payloads:       []string(r.Payloads),
		})
	}
	return rules
}
