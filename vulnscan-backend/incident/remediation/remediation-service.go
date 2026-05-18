package remediation

import (
	"context"
	"fmt"
	"time"
	"vulnscan-backend/model"

	coreContract "vulnscan-backend/incident/core/core-contract"
	remediationContract "vulnscan-backend/incident/remediation/remediation-contract"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type serviceRemediation struct {
	db *db.DB
}

func NewServiceRemediation(database *db.DB) *serviceRemediation {
	return &serviceRemediation{db: database}
}

func (s *serviceRemediation) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceRemediation) SubmitRemediation(ctx context.Context, req remediationContract.RemediationReq) error {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).Where("id = ?", req.ID).First(&incident).Error; err != nil {
		return fmt.Errorf("事件不存在")
	}

	if _, err := model.IncidentSM.Apply(incident.Status, model.IncidentEvtRemediate); err != nil {
		return fmt.Errorf("当前状态不允许提交整改方案: %w", err)
	}

	now := time.Now()
	updates := map[string]interface{}{
		"status":                model.IncidentStatusRemediating,
		"remediation_plan":      req.RemediationPlan,
		"remediation_submit_at": &now,
	}
	if req.RemediationDeadline != nil {
		updates["remediation_deadline"] = req.RemediationDeadline
	}
	if req.RemediationAssignee != "" {
		updates["remediation_assignee"] = req.RemediationAssignee
	}

	return sess.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.SecurityIncident{}).Where("id = ?", req.ID).Updates(updates).Error; err != nil {
			return err
		}

		opLog := model.BuildIncidentOperationLog(
			incident.Id, incident.IncidentNo, model.IncidentOpRemediation,
			"", "", "提交整改",
			map[string]interface{}{
				"remediation_plan":     req.RemediationPlan,
				"remediation_assignee": req.RemediationAssignee,
			},
			model.IncidentSourceSystemLocal,
		)
		return model.CreateIncidentOperationLog(tx, opLog)
	})
}

func (s *serviceRemediation) VerifyRemediation(ctx context.Context, req remediationContract.VerifyRemediationReq) error {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).Where("id = ?", req.ID).First(&incident).Error; err != nil {
		return fmt.Errorf("事件不存在")
	}

	var event string
	if req.Result == "pass" {
		event = model.IncidentEvtVerifyPass
	} else {
		event = model.IncidentEvtVerifyFail
	}
	newStatus, err := model.IncidentSM.Apply(incident.Status, event)
	if err != nil {
		return fmt.Errorf("当前状态不允许验证整改: %w", err)
	}

	now := time.Now()
	updates := map[string]interface{}{"status": newStatus}
	var result string

	if req.Result == "pass" {
		updates["verified_at"] = &now
		result = "验证通过"
	} else {
		result = "验证不通过"
	}

	return sess.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.SecurityIncident{}).Where("id = ?", req.ID).Updates(updates).Error; err != nil {
			return err
		}

		opLog := model.BuildIncidentOperationLog(
			incident.Id, incident.IncidentNo, model.IncidentOpVerify,
			"", "", result,
			map[string]interface{}{
				"result": req.Result,
				"remark": req.Remark,
			},
			model.IncidentSourceSystemLocal,
		)
		return model.CreateIncidentOperationLog(tx, opLog)
	})
}

func (s *serviceRemediation) CloseIncident(ctx context.Context, req remediationContract.CloseIncidentReq) error {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).Where("id = ?", req.ID).First(&incident).Error; err != nil {
		return fmt.Errorf("事件不存在")
	}

	if _, err := model.IncidentSM.Apply(incident.Status, model.IncidentEvtClose); err != nil {
		return err
	}

	now := time.Now()
	updates := map[string]interface{}{
		"status":       model.IncidentStatusClosed,
		"close_reason": req.CloseReason,
		"closed_at":    &now,
	}

	return sess.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.SecurityIncident{}).Where("id = ?", req.ID).Updates(updates).Error; err != nil {
			return err
		}

		opLog := model.BuildIncidentOperationLog(
			incident.Id, incident.IncidentNo, model.IncidentOpClose,
			"", "", "关闭事件",
			map[string]interface{}{
				"close_reason": req.CloseReason,
			},
			model.IncidentSourceSystemLocal,
		)
		return model.CreateIncidentOperationLog(tx, opLog)
	})
}

func (s *serviceRemediation) BatchImport(ctx context.Context, records []remediationContract.IncidentImportRow, createdBy string) (*remediationContract.BatchImportResp, error) {
	sess := s.session()
	resp := &remediationContract.BatchImportResp{
		Total: len(records),
	}

	for _, row := range records {
		err := sess.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Create asset record
			asset := model.IncidentAsset{
				AssetName:  row.AssetName,
				SystemName: row.SystemName,
				DomainIP:   row.DomainIP,
				Unit:       row.Unit,
			}
			if err := tx.Create(&asset).Error; err != nil {
				return err
			}

			// Parse discovery time
			var discoveryTime time.Time
			if row.DiscoveryTime != "" {
				layouts := []string{
					"2006-01-02 15:04:05",
					"2006-01-02",
					"2006/01/02 15:04:05",
					"2006/01/02",
				}
				for _, layout := range layouts {
					if t, e := time.Parse(layout, row.DiscoveryTime); e == nil {
						discoveryTime = t
						break
					}
				}
			}
			if discoveryTime.IsZero() {
				discoveryTime = time.Now()
			}

			// Create metadata record
			metadata := model.IncidentMetadata{
				IncidentType:        row.IncidentType,
				IncidentURL:         row.IncidentURL,
				IncidentDescription: row.Description,
				VendorName:          row.VendorName,
				DiscoveryTime:       discoveryTime,
				CvssScore:           row.CvssScore,
				CveId:               row.CveId,
				OwaspCategory:       row.OwaspCategory,
				ExploitDifficulty:   row.ExploitDiff,
				AffectScope:         row.AffectScope,
			}
			if err := tx.Create(&metadata).Error; err != nil {
				return err
			}

			// Determine SLA level based on incident level
			slaLevel := model.IncidentAutoSLALevel(row.Level)
			slaHours := model.IncidentSLAHours(slaLevel)
			now := time.Now()
			var slaDeadline *time.Time
			if slaHours > 0 {
				dl := now.Add(time.Duration(slaHours) * time.Hour)
				slaDeadline = &dl
			}

			// Create incident
			incidentNo := generateIncidentNo()
			incident := model.SecurityIncident{
				FullModel: model.FullModel{
					Id:        qulid.GenerateID(),
					CreatedAt: now,
					CreatedBy: createdBy,
					UpdatedAt: now,
					UpdatedBy: createdBy,
				},
				IncidentNo:      incidentNo,
				Name:            row.Name,
				Level:           row.Level,
				Source:          row.Source,
				Status:          model.IncidentStatusPendingReview,
				ReportTime:      now,
				AssetDetailID:   asset.Id,
				EventMetadataID: metadata.Id,
				SLALevel:        slaLevel,
				SLADeadline:     slaDeadline,
				SLAStatus:       model.IncidentSLAStatusNormal,
			}
			if err := tx.Create(&incident).Error; err != nil {
				return err
			}

			// Create operation log
			opLog := model.BuildIncidentOperationLog(
				incident.Id, incidentNo, model.IncidentOpBatchImport,
				createdBy, "", "批量导入",
				map[string]interface{}{
					"name":   row.Name,
					"source": row.Source,
					"level":  row.Level,
				},
				model.IncidentSourceSystemLocal,
			)
			return model.CreateIncidentOperationLog(tx, opLog)
		})

		if err != nil {
			resp.Failed++
		} else {
			resp.Success++
		}
	}

	return resp, nil
}

func generateIncidentNo() string {
	return coreContract.GenerateIncidentNo()
}
