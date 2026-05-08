package audit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"vulnscan-backend/model"

	transferContract "vulnscan-backend/circular/transfer/transfer-contract"
	auditContract "vulnscan-backend/incident/audit/audit-contract"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceAudit struct {
	db          *db.DB
	transferSvc transferContract.ServiceTransfer
}

func NewServiceAudit(database *db.DB, transferSvc transferContract.ServiceTransfer) *serviceAudit {
	return &serviceAudit{db: database, transferSvc: transferSvc}
}

func (s *serviceAudit) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceAudit) AIPreAudit(ctx context.Context, id string) (*auditContract.AIPreAuditResp, error) {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).
		Preload("AssetDetail").
		Preload("EventMetadata").
		First(&incident, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("事件不存在: %w", err)
	}

	if incident.Status == model.IncidentStatusReviewPassed {
		return nil, fmt.Errorf("该事件已通过审核，无法进行AI预审")
	}

	result := CalculateRiskScore(&incident)
	aiOpinion := GenerateStructuredOpinion(&incident, result)

	confidence := result.TotalScore / 100.0
	if confidence < 0.3 {
		confidence = 0.3
	}
	if confidence > 0.95 {
		confidence = 0.95
	}

	tagsStr := strings.Join(result.Tags, ",")
	category := result.Category

	updates := map[string]interface{}{
		"ai_pre_status": model.IncidentAiPreStatusDone,
		"ai_opinion":    aiOpinion,
		"ai_confidence": confidence,
		"risk_score":    result.TotalScore,
		"ai_tags":       tagsStr,
		"ai_category":   category,
	}
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新事件AI预审结果失败: %w", err)
	}

	opLog := model.BuildIncidentOperationLog(
		incident.Id, incident.IncidentNo,
		model.IncidentOpAIPreAudit, "system", "AI引擎",
		"完成",
		map[string]interface{}{
			"risk_score":  result.TotalScore,
			"confidence":  confidence,
			"ai_category": category,
		},
		model.IncidentSourceSystemLocal,
	)
	if err := model.CreateIncidentOperationLog(sess.WithContext(ctx), opLog); err != nil {
		return nil, fmt.Errorf("创建操作日志失败: %w", err)
	}

	resp := &auditContract.AIPreAuditResp{
		AiOpinion:    aiOpinion,
		AiConfidence: confidence,
		RiskScore:    result.TotalScore,
		AiTags:       tagsStr,
		AiCategory:   category,
		RiskDetail:   result,
	}
	return resp, nil
}

func (s *serviceAudit) ManualAudit(ctx context.Context, req auditContract.ManualAuditReq) error {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).
		Preload("AssetDetail").
		Preload("EventMetadata").
		First(&incident, "id = ?", req.ID).Error; err != nil {
		return fmt.Errorf("事件不存在: %w", err)
	}

	if incident.Status == model.IncidentStatusReviewPassed {
		return fmt.Errorf("该事件已通过审核，无法重复审核")
	}

	updates := make(map[string]interface{})
	var resultText string

	switch req.AuditResult {
	case "success":
		updates["status"] = model.IncidentStatusReviewPassed
		resultText = "审核通过"
	case "fail":
		updates["status"] = model.IncidentStatusReviewFailed
		resultText = "审核不通过"
	default:
		return fmt.Errorf("无效的审核结果: %s", req.AuditResult)
	}

	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("id = ?", req.ID).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新事件状态失败: %w", err)
	}

	opLog := model.BuildIncidentOperationLog(
		incident.Id, incident.IncidentNo,
		model.IncidentOpManualReview, "", "",
		resultText,
		map[string]interface{}{
			"audit_result": req.AuditResult,
			"opinion":      req.Opinion,
		},
		model.IncidentSourceSystemLocal,
	)
	if err := model.CreateIncidentOperationLog(sess.WithContext(ctx), opLog); err != nil {
		return fmt.Errorf("创建操作日志失败: %w", err)
	}

	if req.AuditResult == "success" {
		s.transferToCircular(ctx, sess, &incident, req.Opinion)
	}

	return nil
}

func (s *serviceAudit) transferToCircular(ctx context.Context, sess *gorm.DB, incident *model.SecurityIncident, opinion string) {
	req := transferContract.TransferIncidentReq{
		IncidentNo:   incident.IncidentNo,
		Name:         incident.Name,
		AiOpinion:    incident.AiOpinion,
		AiConfidence: incident.AiConfidence,
		SourceSystem: "security-incident",
	}
	if incident.AssetDetail != nil {
		a := incident.AssetDetail
		req.AssetInfo = &transferContract.TransferAssetInfo{
			AssetName: a.AssetName, SystemName: a.SystemName, DomainIP: a.DomainIP,
			SiteIP: a.SiteIP, Unit: a.Unit, UnitType: a.UnitType, Industry: a.Industry,
			MLPSRecordNo: a.MLPSRecordNo, MLPSLevel: a.MLPSLevel, Region: a.Region,
		}
	}
	if incident.EventMetadata != nil {
		m := incident.EventMetadata
		req.MetadataInfo = &transferContract.TransferMetadataInfo{
			IncidentType: m.IncidentType, IncidentURL: m.IncidentURL,
			IncidentDescription: m.IncidentDescription, CvssScore: m.CvssScore, CveId: m.CveId,
		}
	}

	circularCode, err := s.transferSvc.ReceiveIncident(ctx, req, "system")
	if err != nil {
		slog.Error("流转到通报模块失败", "incident_no", incident.IncidentNo, "error", err)
		return
	}

	transferLog := model.BuildIncidentOperationLog(
		incident.Id, incident.IncidentNo,
		model.IncidentOpTransfer, "system", "系统",
		"流转成功",
		map[string]interface{}{
			"circular_code": circularCode,
			"target_system": "circular",
		},
		model.IncidentSourceSystemLocal,
	)
	_ = model.CreateIncidentOperationLog(sess.WithContext(ctx), transferLog)
	slog.Info("事件已流转到通报模块", "incident_no", incident.IncidentNo, "circular_code", circularCode)
}

func (s *serviceAudit) AIClassify(ctx context.Context, id string) (*auditContract.ClassifyResult, error) {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).
		Preload("AssetDetail").
		Preload("EventMetadata").
		First(&incident, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("事件不存在: %w", err)
	}

	result := ClassifyIncident(&incident)

	tagsStr := strings.Join(result.Tags, ",")
	updates := map[string]interface{}{
		"ai_tags":     tagsStr,
		"ai_category": result.Category,
	}
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新事件分类结果失败: %w", err)
	}

	return &result, nil
}
