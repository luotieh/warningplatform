package assetmgr

import (
	ac "vulnscan-backend/assetmgr/assetmgr-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type serviceRisk struct {
	db *db.DB
}

func NewServiceRisk(database *db.DB) *serviceRisk {
	return &serviceRisk{db: database}
}

func (s *serviceRisk) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceRisk) List(req ac.RiskListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.AssetRiskScore, int64, error) {
	var items []model.AssetRiskScore
	var count int64

	q := s.session().Model(&model.AssetRiskScore{}).Scopes(scopes...)
	if req.MinScore > 0 {
		q = q.Where("total_score >= ?", req.MinScore)
	}
	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	page, size := req.Page, req.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}
	err := q.Order("total_score DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error
	return items, count, err
}

func (s *serviceRisk) GetByAssetID(assetID string) (*model.AssetRiskScore, error) {
	var item model.AssetRiskScore
	if err := s.session().Where("asset_id = ?", assetID).First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *serviceRisk) Recalculate(assetID string) error {
	sess := s.session()

	var vulnCount int64
	sess.Model(&model.Vulnerability{}).Where("asset_id = ? AND status NOT IN ?", assetID, []string{"fixed", "ignored"}).Count(&vulnCount)

	var criticalCount int64
	sess.Model(&model.Vulnerability{}).Where("asset_id = ? AND severity = ? AND status NOT IN ?", assetID, model.SeverityCritical, []string{"fixed", "ignored"}).Count(&criticalCount)

	var openPorts int64
	sess.Model(&model.ScanFinding{}).Where("asset_id = ? AND type = ?", assetID, "port_open").Count(&openPorts)

	vulnScore := float64(criticalCount)*10 + float64(vulnCount-criticalCount)*3
	exposureScore := float64(openPorts) * 2
	totalScore := vulnScore + exposureScore
	if totalScore > 100 {
		totalScore = 100
	}

	score := model.AssetRiskScore{
		AssetID:       assetID,
		TotalScore:    totalScore,
		VulnScore:     vulnScore,
		ExposureScore: exposureScore,
		VulnCount:     int(vulnCount),
		CriticalVulns: int(criticalCount),
		OpenPorts:     int(openPorts),
	}

	var existing model.AssetRiskScore
	if err := sess.Where("asset_id = ?", assetID).First(&existing).Error; err == nil {
		return sess.Model(&existing).Updates(map[string]interface{}{
			"total_score":    totalScore,
			"vuln_score":     vulnScore,
			"exposure_score": exposureScore,
			"vuln_count":     vulnCount,
			"critical_vulns": criticalCount,
			"open_ports":     openPorts,
		}).Error
	}
	return sess.Create(&score).Error
}

func (s *serviceRisk) RecalculateAll() (int, error) {
	var assets []model.Asset
	if err := s.session().Select("id").Find(&assets).Error; err != nil {
		return 0, err
	}
	count := 0
	for _, a := range assets {
		if err := s.Recalculate(a.ID); err == nil {
			count++
		}
	}
	return count, nil
}

var _ ac.ServiceRisk = (*serviceRisk)(nil)
