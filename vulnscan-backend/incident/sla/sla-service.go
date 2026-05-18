package sla

import (
	"context"
	"fmt"
	"time"
	"vulnscan-backend/model"

	slaContract "vulnscan-backend/incident/sla/sla-contract"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceSLA struct {
	db *db.DB
}

func NewServiceSLA(database *db.DB) *serviceSLA {
	return &serviceSLA{db: database}
}

func (s *serviceSLA) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceSLA) GetSLAOverview(ctx context.Context) (*slaContract.SLAOverviewResp, error) {
	sess := s.session()
	resp := &slaContract.SLAOverviewResp{}

	// Count total incidents with SLA tracking enabled (sla_level > 0)
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("sla_level > 0").
		Count(&resp.TotalTracked).Error; err != nil {
		return nil, err
	}

	if resp.TotalTracked == 0 {
		resp.UpcomingDeadlines = []slaContract.SLADeadlineItem{}
		return resp, nil
	}

	// Count by SLA status
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("sla_level > 0 AND sla_status = ?", model.IncidentSLAStatusNormal).
		Count(&resp.NormalCount).Error; err != nil {
		return nil, err
	}
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("sla_level > 0 AND sla_status = ?", model.IncidentSLAStatusWarning).
		Count(&resp.WarningCount).Error; err != nil {
		return nil, err
	}
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("sla_level > 0 AND sla_status = ?", model.IncidentSLAStatusBreached).
		Count(&resp.BreachedCount).Error; err != nil {
		return nil, err
	}
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("sla_level > 0 AND sla_status = ?", model.IncidentSLAStatusEscalated).
		Count(&resp.EscalatedCount).Error; err != nil {
		return nil, err
	}

	// Calculate compliance rate: normal / total
	if resp.TotalTracked > 0 {
		resp.ComplianceRate = float64(resp.NormalCount) / float64(resp.TotalTracked)
	}

	// Get upcoming deadlines (within next 24 hours, not closed)
	now := time.Now()
	next24h := now.Add(24 * time.Hour)

	var incidents []model.SecurityIncident
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("sla_deadline IS NOT NULL AND sla_deadline <= ? AND sla_deadline >= ? AND status != ?",
			next24h, now, model.IncidentStatusClosed).
		Order("sla_deadline ASC").
		Limit(20).
		Find(&incidents).Error; err != nil {
		return nil, err
	}

	resp.UpcomingDeadlines = make([]slaContract.SLADeadlineItem, 0, len(incidents))
	for _, inc := range incidents {
		if inc.SLADeadline == nil {
			continue
		}
		remainingMin := int(inc.SLADeadline.Sub(now).Minutes())
		if remainingMin < 0 {
			remainingMin = 0
		}
		resp.UpcomingDeadlines = append(resp.UpcomingDeadlines, slaContract.SLADeadlineItem{
			IncidentId:   inc.Id,
			IncidentNo:   inc.IncidentNo,
			IncidentName: inc.Name,
			Level:        inc.Level,
			SLALevel:     inc.SLALevel,
			SLADeadline:  *inc.SLADeadline,
			RemainingMin: remainingMin,
			Status:       inc.SLAStatus,
		})
	}

	return resp, nil
}

func (s *serviceSLA) SetSLA(ctx context.Context, req slaContract.SLASetReq) error {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).Where("id = ?", req.ID).First(&incident).Error; err != nil {
		return fmt.Errorf("事件不存在")
	}

	slaHours := model.IncidentSLAHours(req.SLALevel)
	updates := map[string]interface{}{
		"sla_level":  req.SLALevel,
		"sla_status": model.IncidentSLAStatusNormal,
	}

	if slaHours > 0 {
		deadline := time.Now().Add(time.Duration(slaHours) * time.Hour)
		updates["sla_deadline"] = &deadline
	} else {
		updates["sla_deadline"] = nil
	}

	return sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("id = ?", req.ID).
		Updates(updates).Error
}

func (s *serviceSLA) CheckAndUpdateSLA(ctx context.Context) (*slaContract.SLACheckResult, error) {
	sess := s.session()
	result := &slaContract.SLACheckResult{}

	// Find all incidents with SLA deadline set and not closed
	var incidents []model.SecurityIncident
	if err := sess.WithContext(ctx).
		Where("sla_deadline IS NOT NULL AND status != ?", model.IncidentStatusClosed).
		Find(&incidents).Error; err != nil {
		return nil, err
	}

	result.TotalChecked = len(incidents)
	now := time.Now()
	twoHoursFromNow := now.Add(2 * time.Hour)

	for _, inc := range incidents {
		if inc.SLADeadline == nil {
			continue
		}

		var newStatus int
		needUpdate := false

		if now.After(*inc.SLADeadline) {
			// Past deadline
			if inc.SLAStatus == model.IncidentSLAStatusNormal ||
				inc.SLAStatus == model.IncidentSLAStatusWarning {
				newStatus = model.IncidentSLAStatusBreached
				needUpdate = true
				result.Breached++

				escalatedAt := now
				if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
					Where("id = ?", inc.Id).
					Updates(map[string]interface{}{
						"sla_status":       newStatus,
						"sla_escalated_at": &escalatedAt,
					}).Error; err != nil {
					continue
				}
				result.Escalated++
			}
		} else if inc.SLADeadline.Before(twoHoursFromNow) {
			// Within 2 hours of deadline
			if inc.SLAStatus == model.IncidentSLAStatusNormal {
				newStatus = model.IncidentSLAStatusWarning
				needUpdate = true
				result.Warned++
			}
		}

		if needUpdate && newStatus == model.IncidentSLAStatusWarning {
			if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
				Where("id = ?", inc.Id).
				Update("sla_status", newStatus).Error; err != nil {
				continue
			}
		}

		if needUpdate {
			result.Updated++
		}
	}

	return result, nil
}
