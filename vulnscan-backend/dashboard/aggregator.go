package dashboard

import (
	"context"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
)

type Aggregator struct {
	db *gorm.DB
}

func NewAggregator(db *gorm.DB) *Aggregator {
	return &Aggregator{db: db}
}

func (a *Aggregator) GetSecurityPosture(ctx context.Context) (*SecurityPosture, error) {
	posture := &SecurityPosture{
		SeverityDist: make(map[string]int),
		WorkerStatus: make(map[string]int),
	}

	var totalAssets int64
	a.db.WithContext(ctx).Model(&model.Asset{}).Count(&totalAssets)
	posture.TotalAssets = int(totalAssets)

	var totalVulns int64
	a.db.WithContext(ctx).Model(&model.Vulnerability{}).Count(&totalVulns)
	posture.TotalVulns = int(totalVulns)

	var severityCounts []struct {
		Severity string
		Count    int
	}
	a.db.WithContext(ctx).
		Model(&model.Vulnerability{}).
		Select("severity, count(*) as count").
		Group("severity").
		Find(&severityCounts)

	for _, sc := range severityCounts {
		posture.SeverityDist[sc.Severity] = sc.Count
	}

	posture.RiskScore = calculateRiskScore(posture.SeverityDist)

	var activeTasks int64
	a.db.WithContext(ctx).
		Model(&model.ScanTask{}).
		Where("status = ?", model.TaskStatusRunning).
		Count(&activeTasks)
	posture.ActiveScans = int(activeTasks)

	var workerCounts []struct {
		Status string
		Count  int
	}
	a.db.WithContext(ctx).
		Model(&model.WorkerNode{}).
		Select("status, count(*) as count").
		Group("status").
		Find(&workerCounts)

	for _, wc := range workerCounts {
		posture.WorkerStatus[wc.Status] = wc.Count
	}

	posture.VulnTrend = a.getVulnTrend(ctx, 30)
	posture.TopVulnAssets = a.getTopVulnAssets(ctx, 10)
	posture.MonitorStats = a.getMonitorStats(ctx)
	posture.TopRiskAssets = a.getTopRiskAssets(ctx, 10)

	return posture, nil
}

func (a *Aggregator) getMonitorStats(ctx context.Context) MonitorStats {
	var stats MonitorStats
	a.db.WithContext(ctx).Model(&model.MonitorTask{}).Count(new(int64))
	a.db.WithContext(ctx).Raw(`SELECT
		COUNT(*) as total_tasks,
		SUM(CASE WHEN enabled = true THEN 1 ELSE 0 END) as enabled_tasks
		FROM monitor_tasks`).Scan(&stats)

	type alertCounts struct {
		Total int `gorm:"column:total"`
		Open  int `gorm:"column:open_count"`
	}
	var ac alertCounts
	a.db.WithContext(ctx).Raw(`SELECT
		COUNT(*) as total,
		SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_count
		FROM vs_alert`).Scan(&ac)
	stats.TotalAlerts = ac.Total
	stats.OpenAlerts = ac.Open

	return stats
}

func (a *Aggregator) getTopRiskAssets(ctx context.Context, limit int) []TopRiskAsset {
	var results []TopRiskAsset
	a.db.WithContext(ctx).Raw(`
		SELECT a.id as asset_id, a.name, a.address, a.risk_score,
			COALESCE(v.cnt, 0) as vuln_count,
			COALESCE(al.cnt, 0) as alert_count
		FROM vs_asset a
		LEFT JOIN (SELECT asset_id, COUNT(*) as cnt FROM vs_vulnerability WHERE status != 'fixed' GROUP BY asset_id) v ON v.asset_id = a.id
		LEFT JOIN (SELECT asset_id, COUNT(*) as cnt FROM vs_alert WHERE status = 'open' GROUP BY asset_id) al ON al.asset_id = a.id
		ORDER BY a.risk_score DESC
		LIMIT ?`, limit).Scan(&results)
	return results
}

func (a *Aggregator) getVulnTrend(ctx context.Context, days int) []DataPoint {
	var points []DataPoint

	startDate := time.Now().AddDate(0, 0, -days)
	var trendData []struct {
		Date  time.Time
		Count int
	}

	a.db.WithContext(ctx).
		Model(&model.Vulnerability{}).
		Select("DATE(created_at) as date, count(*) as count").
		Where("created_at >= ?", startDate).
		Group("DATE(created_at)").
		Order("date").
		Find(&trendData)

	for _, td := range trendData {
		points = append(points, DataPoint{
			Timestamp: td.Date,
			Value:     float64(td.Count),
		})
	}

	return points
}

func (a *Aggregator) getTopVulnAssets(ctx context.Context, limit int) []AssetRisk {
	var results []AssetRisk

	a.db.WithContext(ctx).
		Model(&model.Vulnerability{}).
		Select("target as host, count(*) as vuln_count").
		Group("target").
		Order("vuln_count DESC").
		Limit(limit).
		Find(&results)

	for i := range results {
		results[i].RiskScore = min(100, results[i].VulnCount*10)
	}

	return results
}

func (a *Aggregator) QueryMetric(ctx context.Context, query MetricQuery) (*MetricResult, error) {
	result := &MetricResult{
		Name:   query.MetricName,
		Labels: query.Filters,
	}

	switch query.MetricName {
	case "vuln_count":
		result.Points = a.getVulnTrend(ctx, 30)
	case "scan_tasks":
		result.Points = a.getTaskTrend(ctx, 30)
	case "asset_count":
		var count int64
		a.db.WithContext(ctx).Model(&model.Asset{}).Count(&count)
		result.Total = float64(count)
	default:
		slog.Warn("未知指标", "metric", query.MetricName)
	}

	return result, nil
}

func (a *Aggregator) getTaskTrend(ctx context.Context, days int) []DataPoint {
	var points []DataPoint
	startDate := time.Now().AddDate(0, 0, -days)

	var trendData []struct {
		Date  time.Time
		Count int
	}

	a.db.WithContext(ctx).
		Model(&model.ScanTask{}).
		Select("DATE(created_at) as date, count(*) as count").
		Where("created_at >= ?", startDate).
		Group("DATE(created_at)").
		Order("date").
		Find(&trendData)

	for _, td := range trendData {
		points = append(points, DataPoint{
			Timestamp: td.Date,
			Value:     float64(td.Count),
		})
	}

	return points
}

func calculateRiskScore(dist map[string]int) float64 {
	weights := map[string]float64{
		"critical": 10.0,
		"high":     5.0,
		"medium":   2.0,
		"low":      0.5,
		"info":     0.0,
	}

	total := 0.0
	for sev, count := range dist {
		if w, ok := weights[sev]; ok {
			total += w * float64(count)
		}
	}

	score := 100.0 - total
	if score < 0 {
		score = 0
	}
	return score
}
