package sitemonitor

import (
	"context"
	"fmt"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"gorm.io/gorm"
)

// ══ 执行记录 ══

func (s *serviceMonitor) ListExecutions(ctx context.Context, req contract.ExecutionListReq, scopes ...func(*gorm.DB) *gorm.DB) (int64, []model.MonitorExecution, error) {
	query := s.session().WithContext(ctx).Model(&model.MonitorExecution{}).
		Joins("LEFT JOIN monitor_targets ON monitor_targets.id = monitor_executions.target_id").
		Scopes(scopes...)
	if req.TargetID != "" {
		query = query.Where("target_id = ?", req.TargetID)
	}
	if req.PathTaskID != "" {
		query = query.Where("path_task_id = ?", req.PathTaskID)
	}
	if req.Dimension != "" {
		query = query.Where("dimension = ?", req.Dimension)
	}
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}
	if req.HasIssue == "true" {
		query = query.Where("has_issue = ?", true)
	} else if req.HasIssue == "false" {
		query = query.Where("has_issue = ?", false)
	}
	if req.Disposition != "" {
		query = query.Where("disposition = ?", req.Disposition)
	}
	if req.TimeStart != "" {
		query = query.Where("monitor_executions.created_at >= ?", req.TimeStart)
	}
	if req.TimeEnd != "" {
		query = query.Where("monitor_executions.created_at <= ?", req.TimeEnd)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	var list []model.MonitorExecution
	if err := paginateQuery(query, req.Index, req.Size).Order("monitor_executions.created_at DESC").Find(&list).Error; err != nil {
		return 0, nil, err
	}
	return total, list, nil
}

func (s *serviceMonitor) GetExecutionDetail(ctx context.Context, id string) (*contract.ExecutionDetail, error) {
	var exec model.MonitorExecution
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&exec).Error; err != nil {
		return nil, err
	}
	detail := &contract.ExecutionDetail{MonitorExecution: exec}
	if exec.Dimension == "sensitive_word" {
		var wr model.MonitorResultSensitiveWord
		if s.session().WithContext(ctx).Where("execution_id = ?", id).First(&wr).Error == nil {
			detail.WordResult = &wr
			var matches []model.MonitorResultSensitiveWordMatch
			s.session().WithContext(ctx).Where("result_id = ?", wr.ID).Find(&matches)
			detail.WordMatches = matches
		}
	}
	if exec.Dimension == "sensitive_file" {
		var fr model.MonitorResultSensitiveFile
		if s.session().WithContext(ctx).Where("execution_id = ?", id).First(&fr).Error == nil {
			detail.FileResult = &fr
			var findings []model.MonitorResultSensitiveFileFinding
			s.session().WithContext(ctx).Where("result_id = ?", fr.ID).Find(&findings)
			detail.FileFindings = findings
		}
	}
	if exec.Dimension == "availability" {
		var baseline model.MonitorPerfBaseline
		if exec.PathTaskID != "" && s.session().WithContext(ctx).Where("task_id = ?", exec.PathTaskID).First(&baseline).Error == nil {
			detail.PerfBaseline = &baseline
		}
	}
	return detail, nil
}

func (s *serviceMonitor) GetEvidenceAsset(ctx context.Context, executionID, assetType string) ([]byte, string, error) {
	if s.nats == nil {
		return nil, "", fmt.Errorf("NATS 未连接")
	}
	var exec model.MonitorExecution
	if err := s.session().WithContext(ctx).Where("id = ?", executionID).First(&exec).Error; err != nil {
		return nil, "", fmt.Errorf("执行记录不存在")
	}

	objKey := fmt.Sprintf("evidence/%s/%s", executionID, assetType)
	contentType := "application/octet-stream"

	switch assetType {
	case "html", "text":
		data, err := s.nats.ObjGetGzip(ctx, objKey)
		if err != nil {
			return nil, "", err
		}
		if assetType == "html" {
			contentType = "text/html; charset=utf-8"
		} else {
			contentType = "text/plain; charset=utf-8"
		}
		return data, contentType, nil
	case "screenshot":
		data, err := s.nats.ObjGetRaw(ctx, objKey)
		if err != nil {
			return nil, "", err
		}
		contentType = "image/png"
		return data, contentType, nil
	default:
		data, err := s.nats.ObjGetRaw(ctx, objKey)
		if err != nil {
			return nil, "", err
		}
		return data, contentType, nil
	}
}

func (s *serviceMonitor) DeleteExecution(ctx context.Context, id string) error {
	return s.session().WithContext(ctx).Where("id = ?", id).Delete(&model.MonitorExecution{}).Error
}

func (s *serviceMonitor) BatchDeleteExecutions(ctx context.Context, ids []string) error {
	return s.session().WithContext(ctx).Where("id IN ?", ids).Delete(&model.MonitorExecution{}).Error
}

func (s *serviceMonitor) UpdateDisposition(ctx context.Context, id, disposition, remark, username string) error {
	now := time.Now()
	return s.session().WithContext(ctx).Model(&model.MonitorExecution{}).Where("id = ?", id).Updates(map[string]any{
		"disposition":        disposition,
		"disposition_remark": remark,
		"disposed_by":        username,
		"disposed_at":        &now,
	}).Error
}

func (s *serviceMonitor) BatchUpdateDisposition(ctx context.Context, ids []string, disposition, remark, username string) error {
	now := time.Now()
	return s.session().WithContext(ctx).Model(&model.MonitorExecution{}).Where("id IN ?", ids).Updates(map[string]any{
		"disposition":        disposition,
		"disposition_remark": remark,
		"disposed_by":        username,
		"disposed_at":        &now,
	}).Error
}
