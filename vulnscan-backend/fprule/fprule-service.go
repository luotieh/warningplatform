package fprule

import (
	"fmt"

	fpruleContract "vulnscan-backend/fprule/fprule-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type serviceFPRule struct {
	db *db.DB
}

func NewServiceFPRule(database *db.DB) *serviceFPRule {
	return &serviceFPRule{db: database}
}

func (s *serviceFPRule) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *serviceFPRule) List(query fpruleContract.FPRuleQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.FPRule, int64, error) {
	var items []model.FPRule
	var count int64

	tx := s.session().Model(&model.FPRule{}).Scopes(scopes...)

	if query.Keyword != "" {
		tx = tx.Where("name LIKE ? OR match_value LIKE ? OR reason LIKE ?",
			"%"+query.Keyword+"%", "%"+query.Keyword+"%", "%"+query.Keyword+"%")
	}
	if query.MatchType != "" {
		tx = tx.Where("match_type = ?", query.MatchType)
	}
	if query.Enabled != nil {
		tx = tx.Where("enabled = ?", *query.Enabled)
	}

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 || query.PageSize > 100 {
		query.PageSize = 20
	}
	offset := (query.Page - 1) * query.PageSize

	if err := tx.Offset(offset).Limit(query.PageSize).Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, count, nil
}

func (s *serviceFPRule) GetByID(id string) (*model.FPRule, error) {
	var item model.FPRule
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *serviceFPRule) Create(item *model.FPRule) error {
	if item.ID == "" {
		item.ID = qulid.GenerateID()
	}
	return s.session().Create(item).Error
}

func (s *serviceFPRule) Update(id string, updates map[string]any) error {
	return s.session().Model(&model.FPRule{}).Where("id = ?", id).Updates(updates).Error
}

func (s *serviceFPRule) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.FPRule{}).Error
}

func (s *serviceFPRule) Toggle(id string) error {
	var item model.FPRule
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return err
	}
	return s.session().Model(&item).Update("enabled", !item.Enabled).Error
}

func (s *serviceFPRule) GetActiveRules() ([]model.FPRule, error) {
	var items []model.FPRule
	if err := s.session().Where("enabled = ?", true).Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (s *serviceFPRule) IncrHitCount(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return s.session().Model(&model.FPRule{}).Where("id IN ?", ids).
		UpdateColumn("hit_count", gorm.Expr("hit_count + 1")).Error
}

func (s *serviceFPRule) MarkFromFinding(findingID, matchType, reason, userID, organizeID string) (*model.FPRule, error) {
	var finding model.ScanFinding
	if err := s.session().First(&finding, "id = ?", findingID).Error; err != nil {
		return nil, fmt.Errorf("finding not found: %w", err)
	}

	if matchType == "" {
		matchType = model.FPMatchTypeFingerprint
	}

	var matchField, matchValue, name string
	switch matchType {
	case model.FPMatchTypeFingerprint:
		matchField = "target+port+module+type"
		matchValue = fmt.Sprintf("%s:%d:%s:%s", finding.Target, finding.Port, finding.ModuleID, finding.Type)
		name = fmt.Sprintf("FP: %s", finding.Title)
	case model.FPMatchTypeModuleType:
		matchField = "module_id+type"
		matchValue = fmt.Sprintf("%s:%s", finding.ModuleID, finding.Type)
		name = fmt.Sprintf("FP: %s/%s", finding.ModuleID, finding.Type)
	case model.FPMatchTypeTitlePattern:
		matchField = "title"
		matchValue = finding.Title
		name = fmt.Sprintf("FP: %s", finding.Title)
	default:
		matchField = "target+port+module+type"
		matchValue = fmt.Sprintf("%s:%d:%s:%s", finding.Target, finding.Port, finding.ModuleID, finding.Type)
		name = fmt.Sprintf("FP: %s", finding.Title)
	}

	rule := &model.FPRule{
		ID:         qulid.GenerateID(),
		Name:       name,
		MatchType:  matchType,
		MatchField: matchField,
		MatchValue: matchValue,
		Reason:     reason,
		SourceID:   findingID,
		Scope:      "global",
		Enabled:    true,
		CreatedBy:  userID,
		OrganizeID: organizeID,
	}

	if err := s.session().Create(rule).Error; err != nil {
		return nil, err
	}
	return rule, nil
}
