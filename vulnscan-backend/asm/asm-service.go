package asm

import (
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type ServiceASM struct {
	db *db.DB
}

func NewServiceASM(database *db.DB) *ServiceASM {
	return &ServiceASM{db: database}
}

func (s *ServiceASM) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *ServiceASM) ListProjects() ([]model.ASMProject, int64) {
	var projects []model.ASMProject
	var count int64
	q := s.session().Model(&model.ASMProject{})
	q.Count(&count)
	q.Order("created_at DESC").Find(&projects)
	return projects, count
}

func (s *ServiceASM) GetProject(id string) (*model.ASMProject, []model.ASMSeed, error) {
	var project model.ASMProject
	if err := s.session().First(&project, "id = ?", id).Error; err != nil {
		return nil, nil, err
	}
	var seeds []model.ASMSeed
	s.session().Where("project_id = ?", id).Find(&seeds)
	return &project, seeds, nil
}

func (s *ServiceASM) CreateProject(project *model.ASMProject, seeds []model.ASMSeed) error {
	tx := s.session().Begin()
	if err := tx.Create(project).Error; err != nil {
		tx.Rollback()
		return err
	}
	for i := range seeds {
		if err := tx.Create(&seeds[i]).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	tx.Commit()
	return nil
}

func (s *ServiceASM) UpdateProject(id string, updates map[string]interface{}) error {
	return s.session().Model(&model.ASMProject{}).Where("id = ?", id).Updates(updates).Error
}

func (s *ServiceASM) DeleteProject(id string) {
	tx := s.session().Begin()
	tx.Where("project_id = ?", id).Delete(&model.ASMSeed{})
	tx.Where("project_id = ?", id).Delete(&model.ASMDiscoveredAsset{})
	tx.Where("project_id = ?", id).Delete(&model.ASMChange{})
	tx.Where("id = ?", id).Delete(&model.ASMProject{})
	tx.Commit()
}

func (s *ServiceASM) AddSeed(seed *model.ASMSeed) error {
	return s.session().Create(seed).Error
}

func (s *ServiceASM) DeleteSeed(seedID string) {
	s.session().Where("id = ?", seedID).Delete(&model.ASMSeed{})
}

func (s *ServiceASM) GetProjectWithSeeds(projectID string) (*model.ASMProject, []model.ASMSeed, error) {
	var project model.ASMProject
	if err := s.session().First(&project, "id = ?", projectID).Error; err != nil {
		return nil, nil, err
	}
	var seeds []model.ASMSeed
	s.session().Where("project_id = ? AND enabled = ?", projectID, true).Find(&seeds)
	return &project, seeds, nil
}

func (s *ServiceASM) GetPreviousAssets(projectID string) []model.ASMDiscoveredAsset {
	var assets []model.ASMDiscoveredAsset
	s.session().Where("project_id = ?", projectID).Find(&assets)
	return assets
}

func (s *ServiceASM) SaveDiscoveryResults(projectID string, newAssets []model.ASMDiscoveredAsset, changes []model.ASMChange) {
	tx := s.session().Begin()

	var now time.Time
	if len(newAssets) > 0 {
		now = newAssets[0].LastSeen
	} else {
		now = time.Now()
	}

	for i := range newAssets {
		var existing model.ASMDiscoveredAsset
		err := tx.Where("project_id = ? AND type = ? AND value = ?",
			projectID, newAssets[i].Type, newAssets[i].Value).First(&existing).Error
		if err == nil {
			tx.Model(&existing).Updates(map[string]any{
				"source":     newAssets[i].Source,
				"attributes": mergeAttributes(existing.Attributes, newAssets[i].Attributes),
				"risk_score": newAssets[i].RiskScore,
				"status":     "active",
				"last_seen":  newAssets[i].LastSeen,
			})
		} else {
			tx.Create(&newAssets[i])
		}
	}

	// Mark assets not seen this run as inactive
	tx.Model(&model.ASMDiscoveredAsset{}).
		Where("project_id = ? AND last_seen < ?", projectID, now).
		Update("status", "inactive")

	if len(changes) > 0 {
		tx.CreateInBatches(changes, 100)
	}
	tx.Commit()
	s.session().Model(&model.ASMSeed{}).Where("project_id = ?", projectID).Update("last_run_at", time.Now())
}

func mergeAttributes(old, incoming model.JSONMap) model.JSONMap {
	merged := make(model.JSONMap, len(old)+len(incoming))
	for k, v := range old {
		merged[k] = v
	}
	for k, v := range incoming {
		merged[k] = v
	}
	return merged
}

type AssetListQuery struct {
	Index   int    `form:"index"`
	Size    int    `form:"size" binding:"lte=100"`
	Keyword string `form:"keyword"`
	Type    string `form:"type"`
	Status  string `form:"status"`
	MinRisk int    `form:"min_risk"`
	MaxRisk int    `form:"max_risk"`
	Source  string `form:"source"`
}

func (s *ServiceASM) ListDiscoveredAssets(projectID string, query AssetListQuery) ([]model.ASMDiscoveredAsset, int64) {
	var assets []model.ASMDiscoveredAsset
	var count int64
	tx := s.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ?", projectID)

	if query.Keyword != "" {
		tx = tx.Where("value LIKE ?", "%"+query.Keyword+"%")
	}
	if query.Type != "" {
		tx = tx.Where("type = ?", query.Type)
	}
	if query.Status != "" {
		tx = tx.Where("status = ?", query.Status)
	}
	if query.MinRisk > 0 {
		tx = tx.Where("risk_score >= ?", query.MinRisk)
	}
	if query.MaxRisk > 0 {
		tx = tx.Where("risk_score <= ?", query.MaxRisk)
	}
	if query.Source != "" {
		tx = tx.Where("source LIKE ?", "%"+query.Source+"%")
	}

	tx.Count(&count)

	page := query.Index
	if page <= 0 {
		page = 1
	}
	size := query.Size
	if size <= 0 || size > 100 {
		size = 20
	}

	tx.Offset((page - 1) * size).Limit(size).Order("risk_score DESC, last_seen DESC").Find(&assets)
	return assets, count
}

func (s *ServiceASM) GetAllAssets(projectID string) ([]model.ASMDiscoveredAsset, int64) {
	var assets []model.ASMDiscoveredAsset
	var count int64
	q := s.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ?", projectID)
	q.Count(&count)
	q.Order("risk_score DESC").Find(&assets)
	return assets, count
}

func (s *ServiceASM) ListChanges(projectID string) ([]model.ASMChange, int64) {
	var changes []model.ASMChange
	var count int64
	q := s.session().Model(&model.ASMChange{}).Where("project_id = ?", projectID)
	q.Count(&count)
	q.Order("change_at DESC").Limit(200).Find(&changes)
	return changes, count
}

func (s *ServiceASM) ListAlertRules(projectID string) []model.ASMAlertRule {
	var rules []model.ASMAlertRule
	s.session().Where("project_id = ?", projectID).Order("created_at DESC").Find(&rules)
	return rules
}

func (s *ServiceASM) CreateAlertRule(rule *model.ASMAlertRule) error {
	return s.session().Create(rule).Error
}

func (s *ServiceASM) DeleteAlertRule(ruleID string) {
	s.session().Where("id = ?", ruleID).Delete(&model.ASMAlertRule{})
}

type ExposureReportData struct {
	TotalAssets      int64                      `json:"total_assets"`
	TypeDistribution []TypeStat                 `json:"type_distribution"`
	SourceStats      []SourceStat               `json:"source_stats"`
	RiskDistribution []RiskBucket               `json:"risk_distribution"`
	RecentChanges    int64                      `json:"recent_changes"`
	OpenAlerts       int64                      `json:"open_alerts"`
	TopRiskAssets    []model.ASMDiscoveredAsset `json:"top_risk_assets"`
}

type TypeStat struct {
	Type  string `gorm:"column:type" json:"type"`
	Count int64  `gorm:"column:count" json:"count"`
}

type SourceStat struct {
	Source string `gorm:"column:source" json:"source"`
	Count  int64  `gorm:"column:count" json:"count"`
}

type RiskBucket struct {
	Bucket string `json:"bucket"`
	Count  int64  `json:"count"`
}

func (s *ServiceASM) ExposureReport(projectID string) *ExposureReportData {
	var typeStats []TypeStat
	s.session().Model(&model.ASMDiscoveredAsset{}).
		Where("project_id = ?", projectID).
		Select("type, COUNT(*) as count").
		Group("type").Find(&typeStats)

	var sourceStats []SourceStat
	s.session().Model(&model.ASMDiscoveredAsset{}).
		Where("project_id = ?", projectID).
		Select("source, COUNT(*) as count").
		Group("source").Find(&sourceStats)

	var total, highRisk, mediumRisk, lowRisk int64
	s.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ?", projectID).Count(&total)
	s.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ? AND risk_score >= 70", projectID).Count(&highRisk)
	s.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ? AND risk_score >= 40 AND risk_score < 70", projectID).Count(&mediumRisk)
	s.session().Model(&model.ASMDiscoveredAsset{}).Where("project_id = ? AND risk_score < 40", projectID).Count(&lowRisk)

	riskDistribution := []RiskBucket{
		{Bucket: "high (≥70)", Count: highRisk},
		{Bucket: "medium (40-69)", Count: mediumRisk},
		{Bucket: "low (<40)", Count: lowRisk},
	}

	var recentChanges int64
	s.session().Model(&model.ASMChange{}).Where("project_id = ?", projectID).Count(&recentChanges)

	var openAlerts int64
	s.session().Model(&model.Alert{}).Where("source = ? AND status = ?", "asm", "open").Count(&openAlerts)

	var topRiskAssets []model.ASMDiscoveredAsset
	s.session().Where("project_id = ?", projectID).Order("risk_score DESC").Limit(10).Find(&topRiskAssets)

	return &ExposureReportData{
		TotalAssets:      total,
		TypeDistribution: typeStats,
		SourceStats:      sourceStats,
		RiskDistribution: riskDistribution,
		RecentChanges:    recentChanges,
		OpenAlerts:       openAlerts,
		TopRiskAssets:    topRiskAssets,
	}
}
