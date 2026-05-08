package vuln

import (
	"time"

	"vulnscan-backend/model"
	vulnContract "vulnscan-backend/vuln/vuln-contract"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type serviceVuln struct {
	db *db.DB
}

func NewServiceVuln(database *db.DB) *serviceVuln {
	return &serviceVuln{db: database}
}

func (s *serviceVuln) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *serviceVuln) List(query vulnContract.VulnQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Vulnerability, int64, error) {
	var items []model.Vulnerability
	var count int64

	tx := s.session().Model(&model.Vulnerability{}).Scopes(scopes...)

	if query.Keyword != "" {
		tx = tx.Where("title LIKE ? OR target LIKE ?", "%"+query.Keyword+"%", "%"+query.Keyword+"%")
	}
	if query.Severity != "" {
		tx = tx.Where("severity = ?", query.Severity)
	}
	if query.Status != "" {
		tx = tx.Where("status = ?", query.Status)
	}
	if query.TaskID != "" {
		tx = tx.Where("task_id = ?", query.TaskID)
	}
	if query.AssetID != "" {
		tx = tx.Where("asset_id = ?", query.AssetID)
	}
	if query.Category != "" {
		tx = tx.Where("category = ?", query.Category)
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

func (s *serviceVuln) GetByID(id string) (*model.Vulnerability, error) {
	var item model.Vulnerability
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *serviceVuln) Create(item *model.Vulnerability) error {
	return s.session().Create(item).Error
}

func (s *serviceVuln) BatchCreate(items []*model.Vulnerability) (int, error) {
	result := s.session().CreateInBatches(items, 100)
	return int(result.RowsAffected), result.Error
}

func (s *serviceVuln) Update(id string, updates map[string]any) error {
	return s.session().Model(&model.Vulnerability{}).Where("id = ?", id).Updates(updates).Error
}

func (s *serviceVuln) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.Vulnerability{}).Error
}

func (s *serviceVuln) MarkFixed(id string) error {
	return s.changeStatus(id, model.VulnStatusFixed, "", "")
}

func (s *serviceVuln) MarkIgnored(id string, reason string) error {
	return s.changeStatus(id, model.VulnStatusIgnored, reason, "")
}

func (s *serviceVuln) Reopen(id string) error {
	return s.changeStatus(id, model.VulnStatusReopen, "", "")
}

func (s *serviceVuln) changeStatus(id, newStatus, comment, operator string) error {
	sess := s.session()

	var v model.Vulnerability
	if err := sess.First(&v, "id = ?", id).Error; err != nil {
		return err
	}
	oldStatus := v.Status

	updates := map[string]any{"status": newStatus}
	now := time.Now()
	switch newStatus {
	case model.VulnStatusFixed:
		updates["fixed_at"] = &now
	case model.VulnStatusIgnored:
		updates["ignored_at"] = &now
		if comment != "" {
			updates["ignore_reason"] = comment
		}
	case model.VulnStatusReopen:
		updates["fixed_at"] = nil
		updates["ignored_at"] = nil
	}

	if err := sess.Model(&model.Vulnerability{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}

	sess.Create(&model.VulnStatusHistory{
		ID:        qulid.GenerateID(),
		VulnID:    id,
		OldStatus: oldStatus,
		NewStatus: newStatus,
		Comment:   comment,
		Operator:  operator,
	})

	return nil
}

func (s *serviceVuln) GetStatusHistory(vulnID string) ([]model.VulnStatusHistory, error) {
	var items []model.VulnStatusHistory
	err := s.session().Where("vuln_id = ?", vulnID).Order("created_at DESC").Find(&items).Error
	return items, err
}

func (s *serviceVuln) Stats(scopes ...func(*gorm.DB) *gorm.DB) (*vulnContract.VulnStats, error) {
	var stats vulnContract.VulnStats
	tx := s.session().Model(&model.Vulnerability{}).Scopes(scopes...)

	if err := tx.Count(&stats.Total).Error; err != nil {
		return nil, err
	}

	severityCounts := make(map[string]int64)
	rows, err := tx.Select("severity, count(*) as cnt").Group("severity").Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var cnt int64
		if scanErr := rows.Scan(&sev, &cnt); scanErr == nil {
			severityCounts[sev] = cnt
		}
	}
	stats.Critical = severityCounts[model.SeverityCritical]
	stats.High = severityCounts[model.SeverityHigh]
	stats.Medium = severityCounts[model.SeverityMedium]
	stats.Low = severityCounts[model.SeverityLow]
	stats.Info = severityCounts[model.SeverityInfo]

	statusCounts := make(map[string]int64)
	rows2, err := tx.Select("status, count(*) as cnt").Group("status").Rows()
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var st string
		var cnt int64
		if scanErr := rows2.Scan(&st, &cnt); scanErr == nil {
			statusCounts[st] = cnt
		}
	}
	stats.Open = statusCounts[model.VulnStatusOpen]
	stats.Fixed = statusCounts[model.VulnStatusFixed]
	stats.Ignored = statusCounts[model.VulnStatusIgnored]

	return &stats, nil
}
