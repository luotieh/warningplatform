package sitemonitor

import (
	"context"
	"encoding/json"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"gorm.io/gorm"
)

func (s *serviceMonitor) GetDashboardStats(ctx context.Context) (*contract.DashboardStats, error) {
	db := s.session().WithContext(ctx)
	stats := &contract.DashboardStats{}
	db.Model(&model.MonitorTarget{}).Count(&stats.TotalTargets)
	db.Model(&model.MonitorTarget{}).Where("enabled = ?", true).Count(&stats.EnabledTargets)
	db.Model(&model.MonitorPathTask{}).Count(&stats.TotalPathTasks)
	db.Model(&model.MonitorPathTask{}).Where("enabled = ?", true).Count(&stats.EnabledPathTasks)
	db.Model(&model.MonitorExecution{}).Count(&stats.TotalExecutions)
	db.Model(&model.MonitorExecution{}).Where("has_issue = ?", true).Count(&stats.IssueExecutions)
	db.Model(&model.MonitorAgent{}).Where("status = ?", "online").Count(&stats.OnlineAgents)
	db.Model(&model.MonitorAgent{}).Count(&stats.TotalAgents)
	return stats, nil
}

func (s *serviceMonitor) GetTaskExecutionStats(ctx context.Context) (map[string]map[string]*contract.TaskDimStat, error) {
	type row struct {
		PathTaskID string
		Dimension  string
		Total      int64
		IssueCount int64
		PendingCnt int64
		ValidCnt   int64
	}
	var rows []row
	err := s.session().WithContext(ctx).Raw(`
		SELECT path_task_id, dimension,
			COUNT(*) as total,
			SUM(CASE WHEN has_issue = 1 THEN 1 ELSE 0 END) as issue_count,
			SUM(CASE WHEN has_issue = 1 AND disposition = 'pending' THEN 1 ELSE 0 END) as pending_cnt,
			SUM(CASE WHEN has_issue = 1 AND disposition = 'valid' THEN 1 ELSE 0 END) as valid_cnt
		FROM monitor_executions
		WHERE path_task_id IS NOT NULL AND path_task_id != ''
		GROUP BY path_task_id, dimension
	`).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	result := map[string]map[string]*contract.TaskDimStat{}
	for _, r := range rows {
		if result[r.PathTaskID] == nil {
			result[r.PathTaskID] = map[string]*contract.TaskDimStat{}
		}
		result[r.PathTaskID][r.Dimension] = &contract.TaskDimStat{
			Total:        r.Total,
			IssueCount:   r.IssueCount,
			PendingCount: r.PendingCnt,
			ValidCount:   r.ValidCnt,
		}
	}
	return result, nil
}

func applyTrendExecutionFilters(q *gorm.DB, query contract.TaskTrendQuery) *gorm.DB {
	if query.HasIssue == "true" {
		q = q.Where("has_issue = ?", true)
	} else if query.HasIssue == "false" {
		q = q.Where("has_issue = ?", false)
	}
	if query.Disposition != "" {
		q = q.Where("disposition = ?", query.Disposition)
	}
	if query.Status != "" {
		q = q.Where("status = ?", query.Status)
	}
	if query.TimeStart != "" {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", query.TimeStart, time.Local); err == nil {
			q = q.Where("created_at >= ?", t)
		}
	}
	if query.TimeEnd != "" {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", query.TimeEnd, time.Local); err == nil {
			q = q.Where("created_at <= ?", t)
		}
	}
	return q
}

func (s *serviceMonitor) GetTaskTrend(ctx context.Context, pathTaskID string, query contract.TaskTrendQuery) (*contract.TaskTrendResp, error) {
	db := s.session().WithContext(ctx)
	var pt model.MonitorPathTask
	if err := db.Where("id = ?", pathTaskID).First(&pt).Error; err != nil {
		return nil, err
	}
	var target model.MonitorTarget
	if err := db.Where("id = ?", pt.TargetID).First(&target).Error; err != nil {
		return nil, err
	}
	ep, err := ResolvePathTaskURL(&target, &pt)
	if err != nil {
		return nil, err
	}
	hours := query.Hours
	if hours <= 0 {
		hours = 24
	}
	if hours > 720 {
		hours = 720
	}

	resp := &contract.TaskTrendResp{
		TaskID:   pt.ID,
		TaskName: pt.Name,
		URL:      ep.DisplayURL,
	}

	dim := query.Dimension
	if dim == "all" {
		dim = ""
	}

	if dim == "" {
		if err := s.buildAllDimensionsTrend(db, pathTaskID, hours, query, resp); err != nil {
			return nil, err
		}
		return resp, nil
	}
	if dim == "availability" {
		if err := s.buildAvailabilityTrend(db, pathTaskID, hours, query, resp); err != nil {
			return nil, err
		}
		return resp, nil
	}
	if err := s.buildGenericDimensionTrend(db, pathTaskID, dim, hours, query, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *serviceMonitor) buildAllDimensionsTrend(
	db *gorm.DB, pathTaskID string, hours int, query contract.TaskTrendQuery, resp *contract.TaskTrendResp,
) error {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	q := db.Model(&model.MonitorExecution{}).
		Where("path_task_id = ? AND created_at >= ?", pathTaskID, since)
	q = applyTrendExecutionFilters(q, query)
	var execs []model.MonitorExecution
	q.Order("created_at ASC").Find(&execs)

	for _, e := range execs {
		resp.Points = append(resp.Points, contract.TaskTrendPoint{
			Time:        e.CreatedAt.Format("2006-01-02 15:04"),
			Dimension:   e.Dimension,
			Status:      e.Status,
			Disposition: e.Disposition,
			HasIssue:    e.HasIssue,
		})
		summarizeExecution(&resp.Summary, e)
	}
	resp.Summary.TotalChecks = int64(len(execs))
	appendDimensionBriefs(db, pathTaskID, resp)
	return nil
}

func (s *serviceMonitor) buildAvailabilityTrend(
	db *gorm.DB, pathTaskID string, hours int, query contract.TaskTrendQuery, resp *contract.TaskTrendResp,
) error {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	q := db.Model(&model.MonitorExecution{}).
		Where("path_task_id = ? AND dimension = ? AND created_at >= ?", pathTaskID, "availability", since)
	q = applyTrendExecutionFilters(q, query)
	if query.Status == "" {
		q = q.Where("status = ?", "success")
	}
	var execs []model.MonitorExecution
	q.Order("created_at ASC").Find(&execs)

	var totalMS, maxMS, minMS float64
	minMS = 1e9
	for _, e := range execs {
		pt := contract.TaskTrendPoint{
			Time:        e.CreatedAt.Format("2006-01-02 15:04"),
			Dimension:   e.Dimension,
			Status:      e.Status,
			Disposition: e.Disposition,
			HasIssue:    e.HasIssue,
		}
		var rj map[string]any
		if e.ResultJSON != "" {
			if err := json.Unmarshal([]byte(e.ResultJSON), &rj); err == nil {
				pt.Available, _ = rj["available"].(bool)
				if sc, ok := rj["status_code"].(float64); ok {
					pt.StatusCode = int(sc)
				}
				if tm, ok := rj["timing"].(map[string]any); ok {
					pt.TotalMS, _ = tm["total_ms"].(float64)
					pt.DNSMS, _ = tm["dns_ms"].(float64)
					pt.TCPMS, _ = tm["tcp_connect_ms"].(float64)
					pt.TLSMS, _ = tm["tls_handshake_ms"].(float64)
					pt.TTFBMS, _ = tm["ttfb_ms"].(float64)
				}
			}
		}
		resp.Points = append(resp.Points, pt)
		totalMS += pt.TotalMS
		if pt.TotalMS > maxMS {
			maxMS = pt.TotalMS
		}
		if pt.TotalMS > 0 && pt.TotalMS < minMS {
			minMS = pt.TotalMS
		}
		summarizeExecution(&resp.Summary, e)
		if pt.Available {
			resp.Summary.AvailableCount++
		} else if e.Status == "success" {
			resp.Summary.UnavailableCount++
		}
	}
	resp.Summary.TotalChecks = int64(len(execs))
	if resp.Summary.TotalChecks > 0 {
		resp.Summary.AvgResponseMS = totalMS / float64(resp.Summary.TotalChecks)
		resp.Summary.MaxResponseMS = maxMS
		if minMS < 1e9 {
			resp.Summary.MinResponseMS = minMS
		}
		if resp.Summary.AvailableCount+resp.Summary.UnavailableCount > 0 {
			resp.Summary.AvailabilityPct = float64(resp.Summary.AvailableCount) /
				float64(resp.Summary.AvailableCount+resp.Summary.UnavailableCount) * 100
		}
	}
	appendDimensionBriefs(db, pathTaskID, resp)
	return nil
}

func (s *serviceMonitor) buildGenericDimensionTrend(
	db *gorm.DB, pathTaskID, dimension string, hours int, query contract.TaskTrendQuery, resp *contract.TaskTrendResp,
) error {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	q := db.Model(&model.MonitorExecution{}).
		Where("path_task_id = ? AND dimension = ? AND created_at >= ?", pathTaskID, dimension, since)
	q = applyTrendExecutionFilters(q, query)
	var execs []model.MonitorExecution
	q.Order("created_at ASC").Find(&execs)

	for _, e := range execs {
		resp.Points = append(resp.Points, contract.TaskTrendPoint{
			Time:        e.CreatedAt.Format("2006-01-02 15:04"),
			Dimension:   e.Dimension,
			Status:      e.Status,
			Disposition: e.Disposition,
			HasIssue:    e.HasIssue,
		})
		summarizeExecution(&resp.Summary, e)
	}
	resp.Summary.TotalChecks = int64(len(execs))
	appendDimensionBriefs(db, pathTaskID, resp)
	return nil
}

func summarizeExecution(sum *contract.TaskTrendSummary, e model.MonitorExecution) {
	switch e.Status {
	case "success":
		sum.SuccessCount++
	case "failed":
		sum.FailedCount++
	}
	if e.HasIssue {
		sum.IssueCount++
	} else if e.Status == "success" {
		sum.NormalCount++
	}
	if e.HasIssue && e.Disposition == "pending" {
		sum.PendingDisposition++
	}
}

func appendDimensionBriefs(db *gorm.DB, pathTaskID string, resp *contract.TaskTrendResp) {
	for _, dim := range model.MonitorPathDimensions {
		brief := contract.TaskDimBrief{Dimension: dim}
		db.Model(&model.MonitorExecution{}).Where("path_task_id = ? AND dimension = ?", pathTaskID, dim).Count(&brief.Total)
		db.Model(&model.MonitorExecution{}).Where("path_task_id = ? AND dimension = ? AND status = ?", pathTaskID, dim, "success").Count(&brief.SuccessCount)
		db.Model(&model.MonitorExecution{}).Where("path_task_id = ? AND dimension = ? AND status = ?", pathTaskID, dim, "failed").Count(&brief.FailedCount)
		db.Model(&model.MonitorExecution{}).Where("path_task_id = ? AND dimension = ? AND has_issue = ?", pathTaskID, dim, true).Count(&brief.IssueCount)
		var last model.MonitorExecution
		if db.Where("path_task_id = ? AND dimension = ?", pathTaskID, dim).Order("created_at DESC").First(&last).Error == nil {
			brief.LastStatus = last.Status
			brief.LastTime = last.CreatedAt.Format("2006-01-02 15:04:05")
		}
		resp.Dimensions = append(resp.Dimensions, brief)
	}
}
