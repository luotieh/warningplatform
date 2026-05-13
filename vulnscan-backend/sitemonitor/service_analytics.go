package sitemonitor

import (
	"context"
	"encoding/json"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"
)

// ══ Dashboard / Analytics ══

func (s *serviceMonitor) GetDashboardStats(ctx context.Context) (*contract.DashboardStats, error) {
	db := s.session().WithContext(ctx)
	stats := &contract.DashboardStats{}
	db.Model(&model.MonitorTask{}).Count(&stats.TotalTasks)
	db.Model(&model.MonitorTask{}).Where("enabled = ?", true).Count(&stats.EnabledTasks)
	db.Model(&model.MonitorExecution{}).Count(&stats.TotalExecutions)
	db.Model(&model.MonitorExecution{}).Where("has_issue = ?", true).Count(&stats.IssueExecutions)
	db.Model(&model.MonitorAgent{}).Where("status = ?", "online").Count(&stats.OnlineAgents)
	db.Model(&model.MonitorAgent{}).Count(&stats.TotalAgents)
	return stats, nil
}

func (s *serviceMonitor) GetTaskExecutionStats(ctx context.Context) (map[string]map[string]*contract.TaskDimStat, error) {
	type row struct {
		TaskID     string
		Dimension  string
		Total      int64
		IssueCount int64
		PendingCnt int64
		ValidCnt   int64
	}
	var rows []row
	err := s.session().WithContext(ctx).Raw(`
		SELECT task_id, dimension,
			COUNT(*) as total,
			SUM(CASE WHEN has_issue = 1 THEN 1 ELSE 0 END) as issue_count,
			SUM(CASE WHEN has_issue = 1 AND disposition = 'pending' THEN 1 ELSE 0 END) as pending_cnt,
			SUM(CASE WHEN has_issue = 1 AND disposition = 'valid' THEN 1 ELSE 0 END) as valid_cnt
		FROM monitor_executions GROUP BY task_id, dimension
	`).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	result := map[string]map[string]*contract.TaskDimStat{}
	for _, r := range rows {
		if result[r.TaskID] == nil {
			result[r.TaskID] = map[string]*contract.TaskDimStat{}
		}
		result[r.TaskID][r.Dimension] = &contract.TaskDimStat{
			Total:        r.Total,
			IssueCount:   r.IssueCount,
			PendingCount: r.PendingCnt,
			ValidCount:   r.ValidCnt,
		}
	}
	return result, nil
}

func (s *serviceMonitor) GetTaskTrend(ctx context.Context, taskID string, hours int) (*contract.TaskTrendResp, error) {
	db := s.session().WithContext(ctx)

	var task model.MonitorTask
	if err := db.Where("id = ?", taskID).First(&task).Error; err != nil {
		return nil, err
	}

	resp := &contract.TaskTrendResp{
		TaskID:   task.ID,
		TaskName: task.TaskName,
		URL:      task.TargetHomepage,
	}

	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	var execs []model.MonitorExecution
	db.Where("task_id = ? AND dimension = ? AND status = ? AND created_at >= ?",
		taskID, "availability", "success", since).
		Order("created_at ASC").Find(&execs)

	var totalMS, maxMS, minMS float64
	minMS = 1e9
	for _, e := range execs {
		pt := contract.TaskTrendPoint{
			Time:     e.CreatedAt.Format("2006-01-02 15:04"),
			HasIssue: e.HasIssue,
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
		if pt.Available {
			resp.Summary.AvailableCount++
		} else {
			resp.Summary.UnavailableCount++
		}
		if pt.HasIssue {
			resp.Summary.IssueCount++
		}
	}
	resp.Summary.TotalChecks = int64(len(execs))
	if resp.Summary.TotalChecks > 0 {
		resp.Summary.AvgResponseMS = totalMS / float64(resp.Summary.TotalChecks)
		resp.Summary.MaxResponseMS = maxMS
		if minMS < 1e9 {
			resp.Summary.MinResponseMS = minMS
		}
		resp.Summary.AvailabilityPct = float64(resp.Summary.AvailableCount) / float64(resp.Summary.TotalChecks) * 100
	}

	for _, dim := range model.MonitorAllDimensions {
		brief := contract.TaskDimBrief{Dimension: dim}
		db.Model(&model.MonitorExecution{}).
			Where("task_id = ? AND dimension = ?", taskID, dim).
			Count(&brief.Total)
		db.Model(&model.MonitorExecution{}).
			Where("task_id = ? AND dimension = ? AND status = ?", taskID, dim, "success").
			Count(&brief.SuccessCount)
		db.Model(&model.MonitorExecution{}).
			Where("task_id = ? AND dimension = ? AND status = ?", taskID, dim, "failed").
			Count(&brief.FailedCount)
		db.Model(&model.MonitorExecution{}).
			Where("task_id = ? AND dimension = ? AND has_issue = ?", taskID, dim, true).
			Count(&brief.IssueCount)
		var last model.MonitorExecution
		if db.Where("task_id = ? AND dimension = ?", taskID, dim).
			Order("created_at DESC").First(&last).Error == nil {
			brief.LastStatus = last.Status
			brief.LastTime = last.CreatedAt.Format("2006-01-02 15:04:05")
		}
		resp.Dimensions = append(resp.Dimensions, brief)
	}

	return resp, nil
}
