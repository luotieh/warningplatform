package stats

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"math"
	"time"
	"vulnscan-backend/model"

	"vulnscan-backend/incident/audit"
	coreContract "vulnscan-backend/incident/core/core-contract"
	statsContract "vulnscan-backend/incident/stats/stats-contract"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceStats struct {
	db *db.DB
}

func NewServiceStats(database *db.DB) *serviceStats {
	return &serviceStats{db: database}
}

func (s *serviceStats) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

// ─── GetRemediationStats ───

func (s *serviceStats) GetRemediationStats(ctx context.Context) (*statsContract.RemediationStatsResp, error) {
	sess := s.session().WithContext(ctx)
	resp := &statsContract.RemediationStatsResp{}

	if err := sess.Model(&model.SecurityIncident{}).Count(&resp.TotalCount).Error; err != nil {
		return nil, err
	}

	if err := sess.Model(&model.SecurityIncident{}).
		Where("status = ?", model.IncidentStatusClosed).
		Count(&resp.ClosedCount).Error; err != nil {
		return nil, err
	}
	resp.RemediatedCount = resp.ClosedCount

	if err := sess.Model(&model.SecurityIncident{}).
		Where("status = ?", model.IncidentStatusVerifying).
		Count(&resp.VerifyingCount).Error; err != nil {
		return nil, err
	}

	now := time.Now()
	if err := sess.Model(&model.SecurityIncident{}).
		Where("remediation_deadline < ? AND status NOT IN ?", now,
			[]int{model.IncidentStatusClosed, model.IncidentStatusVerifying}).
		Count(&resp.OverdueCount).Error; err != nil {
		return nil, err
	}

	if resp.TotalCount > 0 {
		resp.RemediationRate = float64(resp.RemediatedCount) / float64(resp.TotalCount) * 100
		resp.OverdueRate = float64(resp.OverdueCount) / float64(resp.TotalCount) * 100
		resp.RemediationRate = math.Round(resp.RemediationRate*100) / 100
		resp.OverdueRate = math.Round(resp.OverdueRate*100) / 100
	}

	// Average remediation days for closed incidents
	var avgResult struct {
		AvgDays float64
	}
	sess.Model(&model.SecurityIncident{}).
		Select("AVG(julianday(closed_at) - julianday(created_at)) as avg_days").
		Where("status = ? AND closed_at IS NOT NULL", model.IncidentStatusClosed).
		Scan(&avgResult)
	resp.AvgRemediationDay = math.Round(avgResult.AvgDays*100) / 100

	return resp, nil
}

// ─── GetOverdueList ───

func (s *serviceStats) GetOverdueList(ctx context.Context, req statsContract.OverdueListReq) ([]coreContract.IncidentListItem, int64, error) {
	sess := s.session().WithContext(ctx)
	now := time.Now()
	var count int64

	tx := sess.Model(&model.SecurityIncident{}).
		Where("remediation_deadline < ? AND status NOT IN ?", now,
			[]int{model.IncidentStatusClosed, model.IncidentStatusVerifying})

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	var incidents []model.SecurityIncident
	if err := tx.Preload("AssetDetail").
		Scopes(db.Paginate(req.Index, req.Size)).
		Order("remediation_deadline ASC").
		Find(&incidents).Error; err != nil {
		return nil, 0, err
	}

	items := make([]coreContract.IncidentListItem, len(incidents))
	for i, inc := range incidents {
		items[i] = coreContract.BuildIncidentListItem(inc, now)
	}
	return items, count, nil
}

// ─── GetMultiDimAnalysis ───

func (s *serviceStats) GetMultiDimAnalysis(ctx context.Context, dimension string) ([]statsContract.MultiDimItem, error) {
	sess := s.session().WithContext(ctx)

	var results []statsContract.MultiDimItem

	switch dimension {
	case "level":
		var rows []struct {
			Level int   `gorm:"column:level"`
			Count int64 `gorm:"column:count"`
		}
		if err := sess.Model(&model.SecurityIncident{}).
			Select("level, COUNT(*) as count").
			Group("level").Order("level").
			Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			label := model.IncidentLevelText[r.Level]
			if label == "" {
				label = fmt.Sprintf("等级%d", r.Level)
			}
			results = append(results, statsContract.MultiDimItem{
				Dimension: "level",
				Value:     label,
				Count:     r.Count,
			})
		}

	case "source":
		var rows []struct {
			Source int   `gorm:"column:source"`
			Count  int64 `gorm:"column:count"`
		}
		if err := sess.Model(&model.SecurityIncident{}).
			Select("source, COUNT(*) as count").
			Group("source").Order("source").
			Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			label := model.IncidentSourceText[r.Source]
			if label == "" {
				label = fmt.Sprintf("来源%d", r.Source)
			}
			results = append(results, statsContract.MultiDimItem{
				Dimension: "source",
				Value:     label,
				Count:     r.Count,
			})
		}

	case "status":
		var rows []struct {
			Status int   `gorm:"column:status"`
			Count  int64 `gorm:"column:count"`
		}
		if err := sess.Model(&model.SecurityIncident{}).
			Select("status, COUNT(*) as count").
			Group("status").Order("status").
			Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			label := model.IncidentStatusText[r.Status]
			if label == "" {
				label = fmt.Sprintf("状态%d", r.Status)
			}
			results = append(results, statsContract.MultiDimItem{
				Dimension: "status",
				Value:     label,
				Count:     r.Count,
			})
		}

	case "incident_type":
		var rows []struct {
			IncidentType string `gorm:"column:incident_type"`
			Count        int64  `gorm:"column:count"`
		}
		if err := sess.Model(&model.IncidentMetadata{}).
			Select("incident_type, COUNT(*) as count").
			Joins("INNER JOIN security_incidents ON security_incidents.event_metadata_id = incident_metadata.id AND security_incidents.deleted_at IS NULL").
			Where("incident_type != ''").
			Group("incident_type").Order("count DESC").
			Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			results = append(results, statsContract.MultiDimItem{
				Dimension: "incident_type",
				Value:     r.IncidentType,
				Count:     r.Count,
			})
		}

	default:
		return nil, fmt.Errorf("不支持的维度: %s", dimension)
	}

	return results, nil
}

// ─── GenerateReport ───

func (s *serviceStats) GenerateReport(ctx context.Context, req statsContract.ReportReq) ([]byte, string, error) {
	sess := s.session().WithContext(ctx)

	var startTime, endTime time.Time
	if req.Period == "month" {
		year := req.Year
		month := req.Value
		if year == 0 {
			year = time.Now().Year()
		}
		if month == 0 {
			month = int(time.Now().Month())
		}
		startTime = time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.Local)
		endTime = startTime.AddDate(0, 1, 0)
	} else {
		year := req.Year
		quarter := req.Value
		if year == 0 {
			year = time.Now().Year()
		}
		if quarter == 0 {
			quarter = (int(time.Now().Month())-1)/3 + 1
		}
		startMonth := time.Month((quarter-1)*3 + 1)
		startTime = time.Date(year, startMonth, 1, 0, 0, 0, 0, time.Local)
		endTime = startTime.AddDate(0, 3, 0)
	}

	var incidents []model.SecurityIncident
	if err := sess.Preload("AssetDetail").Preload("EventMetadata").
		Where("created_at >= ? AND created_at < ?", startTime, endTime).
		Order("created_at DESC").
		Find(&incidents).Error; err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	// UTF-8 BOM for Excel compatibility
	buf.Write([]byte{0xEF, 0xBB, 0xBF})
	w := csv.NewWriter(&buf)

	header := []string{"事件编号", "事件名称", "等级", "来源", "状态", "资产名称", "隶属单位", "事件类型", "上报时间", "创建时间"}
	_ = w.Write(header)

	for _, inc := range incidents {
		assetName := ""
		unit := ""
		if inc.AssetDetail != nil {
			assetName = inc.AssetDetail.AssetName
			unit = inc.AssetDetail.Unit
		}
		incType := ""
		if inc.EventMetadata != nil {
			incType = inc.EventMetadata.IncidentType
		}
		row := []string{
			inc.IncidentNo,
			inc.Name,
			model.IncidentLevelText[inc.Level],
			model.IncidentSourceText[inc.Source],
			model.IncidentStatusText[inc.Status],
			assetName,
			unit,
			incType,
			inc.ReportTime.Format("2006-01-02 15:04:05"),
			inc.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		_ = w.Write(row)
	}
	w.Flush()

	filename := fmt.Sprintf("incident_report_%s_%d_%d.csv", req.Period, req.Year, req.Value)
	return buf.Bytes(), filename, nil
}

// ─── ExportBatch ───

func (s *serviceStats) ExportBatch(ctx context.Context, ids []string, format string) ([]byte, string, error) {
	sess := s.session().WithContext(ctx)

	var incidents []model.SecurityIncident
	if err := sess.Preload("AssetDetail").Preload("EventMetadata").
		Where("id IN ?", ids).
		Find(&incidents).Error; err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	buf.Write([]byte{0xEF, 0xBB, 0xBF})
	w := csv.NewWriter(&buf)

	header := []string{"事件编号", "事件名称", "等级", "来源", "状态", "资产名称", "隶属单位", "事件类型", "风险评分", "创建时间"}
	_ = w.Write(header)

	for _, inc := range incidents {
		assetName := ""
		unit := ""
		if inc.AssetDetail != nil {
			assetName = inc.AssetDetail.AssetName
			unit = inc.AssetDetail.Unit
		}
		incType := ""
		if inc.EventMetadata != nil {
			incType = inc.EventMetadata.IncidentType
		}
		row := []string{
			inc.IncidentNo,
			inc.Name,
			model.IncidentLevelText[inc.Level],
			model.IncidentSourceText[inc.Source],
			model.IncidentStatusText[inc.Status],
			assetName,
			unit,
			incType,
			fmt.Sprintf("%.1f", inc.RiskScore),
			inc.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		_ = w.Write(row)
	}
	w.Flush()

	filename := fmt.Sprintf("incidents_export_%s.csv", time.Now().Format("20060102150405"))
	return buf.Bytes(), filename, nil
}

// ─── ExportSingle ───

func (s *serviceStats) ExportSingle(ctx context.Context, id string, format string) ([]byte, string, error) {
	sess := s.session().WithContext(ctx)

	var incident model.SecurityIncident
	if err := sess.Preload("AssetDetail").Preload("EventMetadata").
		First(&incident, "id = ?", id).Error; err != nil {
		return nil, "", fmt.Errorf("事件不存在: %w", err)
	}

	var buf bytes.Buffer
	buf.Write([]byte{0xEF, 0xBB, 0xBF})
	w := csv.NewWriter(&buf)

	header := []string{"字段", "值"}
	_ = w.Write(header)

	_ = w.Write([]string{"事件编号", incident.IncidentNo})
	_ = w.Write([]string{"事件名称", incident.Name})
	_ = w.Write([]string{"等级", model.IncidentLevelText[incident.Level]})
	_ = w.Write([]string{"来源", model.IncidentSourceText[incident.Source]})
	_ = w.Write([]string{"状态", model.IncidentStatusText[incident.Status]})
	_ = w.Write([]string{"风险评分", fmt.Sprintf("%.1f", incident.RiskScore)})
	_ = w.Write([]string{"AI标签", incident.AiTags})
	_ = w.Write([]string{"AI分类", incident.AiCategory})
	_ = w.Write([]string{"创建时间", incident.CreatedAt.Format("2006-01-02 15:04:05")})

	if incident.AssetDetail != nil {
		a := incident.AssetDetail
		_ = w.Write([]string{"资产名称", a.AssetName})
		_ = w.Write([]string{"系统名称", a.SystemName})
		_ = w.Write([]string{"域名/IP", a.DomainIP})
		_ = w.Write([]string{"隶属单位", a.Unit})
		_ = w.Write([]string{"所属行业", a.Industry})
		_ = w.Write([]string{"等保等级", a.MLPSLevel})
		_ = w.Write([]string{"归属地", a.Region})
	}

	if incident.EventMetadata != nil {
		m := incident.EventMetadata
		_ = w.Write([]string{"事件类型", m.IncidentType})
		_ = w.Write([]string{"隐患URL", m.IncidentURL})
		_ = w.Write([]string{"事件描述", m.IncidentDescription})
		_ = w.Write([]string{"CVE编号", m.CveId})
		_ = w.Write([]string{"CVSS评分", fmt.Sprintf("%.1f", m.CvssScore)})
		_ = w.Write([]string{"OWASP分类", m.OwaspCategory})
	}

	_ = w.Write([]string{"整改方案", incident.RemediationPlan})
	_ = w.Write([]string{"整改责任人", incident.RemediationAssignee})
	if incident.RemediationDeadline != nil {
		_ = w.Write([]string{"整改截止日期", incident.RemediationDeadline.Format("2006-01-02 15:04:05")})
	}
	_ = w.Write([]string{"关闭原因", incident.CloseReason})

	w.Flush()

	filename := fmt.Sprintf("incident_%s.csv", incident.IncidentNo)
	return buf.Bytes(), filename, nil
}

// ─── GetTrendPrediction ───

func (s *serviceStats) GetTrendPrediction(ctx context.Context, rangeType string, predictDays int) (*statsContract.TrendPrediction, error) {
	historical, err := s.getChartByTrend(ctx, rangeType)
	if err != nil {
		return nil, err
	}

	result := audit.PredictTrend(historical, predictDays)
	return &result, nil
}

// getChartByTrend replicates the core GetChartByTrend logic for internal use.
func (s *serviceStats) getChartByTrend(ctx context.Context, rangeType string) ([]coreContract.ChartTrendItem, error) {
	sess := s.session().WithContext(ctx)

	days := 30
	switch rangeType {
	case "7d":
		days = 7
	case "14d":
		days = 14
	case "90d":
		days = 90
	default:
		days = 30
	}

	startDate := time.Now().AddDate(0, 0, -days)
	var rows []struct {
		Date  string `gorm:"column:date"`
		Count int64  `gorm:"column:count"`
	}

	if err := sess.Model(&model.SecurityIncident{}).
		Select("DATE(created_at) as date, COUNT(*) as count").
		Where("created_at >= ?", startDate).
		Group("DATE(created_at)").
		Order("date ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}

	dateCountMap := make(map[string]int64)
	for _, r := range rows {
		dateCountMap[r.Date] = r.Count
	}

	result := make([]coreContract.ChartTrendItem, 0, days)
	for i := 0; i < days; i++ {
		d := startDate.AddDate(0, 0, i)
		dateStr := d.Format("2006-01-02")
		result = append(result, coreContract.ChartTrendItem{
			Date:  dateStr,
			Count: dateCountMap[dateStr],
		})
	}

	return result, nil
}

// ─── GetAIAnalysis ───

func (s *serviceStats) GetAIAnalysis(ctx context.Context) (*statsContract.AIAnalysisSummary, error) {
	sess := s.session().WithContext(ctx)
	now := time.Now()

	var total, urgentCount, highCount, overdueCount, pendingCount int64

	sess.Model(&model.SecurityIncident{}).Count(&total)
	sess.Model(&model.SecurityIncident{}).Where("level = ?", model.IncidentLevelUrgent).Count(&urgentCount)
	sess.Model(&model.SecurityIncident{}).Where("level = ?", model.IncidentLevelHigh).Count(&highCount)
	sess.Model(&model.SecurityIncident{}).
		Where("remediation_deadline < ? AND status NOT IN ?", now,
			[]int{model.IncidentStatusClosed, model.IncidentStatusVerifying}).
		Count(&overdueCount)
	sess.Model(&model.SecurityIncident{}).
		Where("status IN ?", []int{model.IncidentStatusPendingReview, model.IncidentStatusRemediation}).
		Count(&pendingCount)

	// Overall risk level
	var riskScore float64
	if total > 0 {
		riskScore = float64(urgentCount*40+highCount*25+overdueCount*20+pendingCount*15) / float64(total)
	}
	if riskScore > 100 {
		riskScore = 100
	}

	overallRisk := "低"
	if riskScore >= 70 {
		overallRisk = "高"
	} else if riskScore >= 40 {
		overallRisk = "中"
	}

	// Hot categories
	var catRows []struct {
		Category string `gorm:"column:ai_category"`
		Count    int64  `gorm:"column:count"`
	}
	sess.Model(&model.SecurityIncident{}).
		Select("ai_category, COUNT(*) as count").
		Where("ai_category != ''").
		Group("ai_category").
		Order("count DESC").
		Limit(5).
		Find(&catRows)

	hotCategories := make([]statsContract.HotCategory, len(catRows))
	for i, r := range catRows {
		var ratio float64
		if total > 0 {
			ratio = math.Round(float64(r.Count)/float64(total)*10000) / 100
		}
		hotCategories[i] = statsContract.HotCategory{
			Name:  r.Category,
			Count: r.Count,
			Ratio: ratio,
		}
	}

	topRiskAreas := make([]string, 0)
	for _, cat := range hotCategories {
		if len(topRiskAreas) < 3 {
			topRiskAreas = append(topRiskAreas, cat.Name)
		}
	}

	// Trend direction: compare last 7 days vs previous 7 days
	var recentCount, previousCount int64
	sevenDaysAgo := now.AddDate(0, 0, -7)
	fourteenDaysAgo := now.AddDate(0, 0, -14)
	sess.Model(&model.SecurityIncident{}).Where("created_at >= ?", sevenDaysAgo).Count(&recentCount)
	sess.Model(&model.SecurityIncident{}).Where("created_at >= ? AND created_at < ?", fourteenDaysAgo, sevenDaysAgo).Count(&previousCount)

	trendDirection := "平稳"
	if previousCount > 0 {
		changeRate := float64(recentCount-previousCount) / float64(previousCount)
		if changeRate > 0.2 {
			trendDirection = "上升"
		} else if changeRate < -0.2 {
			trendDirection = "下降"
		}
	} else if recentCount > 0 {
		trendDirection = "上升"
	}

	// Recommendations
	recommendations := make([]string, 0)
	if overdueCount > 0 {
		recommendations = append(recommendations, fmt.Sprintf("当前有 %d 个事件已超期未处理，建议优先处置", overdueCount))
	}
	if urgentCount > 0 {
		recommendations = append(recommendations, fmt.Sprintf("存在 %d 个紧急级别事件，建议立即关注", urgentCount))
	}
	if pendingCount > 0 {
		recommendations = append(recommendations, fmt.Sprintf("有 %d 个事件待审核或待整改，建议加快处理进度", pendingCount))
	}
	if trendDirection == "上升" {
		recommendations = append(recommendations, "近期事件数量呈上升趋势，建议加强安全防护")
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "当前安全态势总体平稳")
	}

	summary := fmt.Sprintf("共 %d 个安全事件，其中紧急 %d 个、高危 %d 个、超期 %d 个、待处理 %d 个",
		total, urgentCount, highCount, overdueCount, pendingCount)

	return &statsContract.AIAnalysisSummary{
		OverallRisk:     overallRisk,
		RiskScore:       math.Round(riskScore*100) / 100,
		Summary:         summary,
		TopRiskAreas:    topRiskAreas,
		TrendDirection:  trendDirection,
		Recommendations: recommendations,
		HotCategories:   hotCategories,
	}, nil
}

// ─── GetAssetProfile ───

func (s *serviceStats) GetAssetProfile(ctx context.Context, req statsContract.AssetProfileReq) (*statsContract.AssetProfileResp, error) {
	sess := s.session().WithContext(ctx)
	now := time.Now()

	// Find asset by asset_name, domain_ip, or unit
	assetTx := sess.Model(&model.IncidentAsset{})
	if req.AssetName != "" {
		assetTx = assetTx.Where("asset_name = ?", req.AssetName)
	}
	if req.DomainIP != "" {
		assetTx = assetTx.Where("domain_ip = ?", req.DomainIP)
	}
	if req.Unit != "" {
		assetTx = assetTx.Where("unit = ?", req.Unit)
	}

	var asset model.IncidentAsset
	if err := assetTx.First(&asset).Error; err != nil {
		return nil, fmt.Errorf("资产不存在: %w", err)
	}

	// Get all incidents linked to this asset
	var incidents []model.SecurityIncident
	sess.Where("asset_detail_id = ?", asset.Id).Find(&incidents)

	var totalCount, openCount, closedCount, overdueCount int64
	levelMap := make(map[int]int64)
	for _, inc := range incidents {
		totalCount++
		if inc.Status == model.IncidentStatusClosed {
			closedCount++
		} else {
			openCount++
		}
		if inc.RemediationDeadline != nil && inc.RemediationDeadline.Before(now) &&
			inc.Status != model.IncidentStatusClosed && inc.Status != model.IncidentStatusVerifying {
			overdueCount++
		}
		levelMap[inc.Level]++
	}

	// Level distribution
	levelDistro := make([]coreContract.ChartTypeItem, 0)
	for level := model.IncidentLevelLow; level <= model.IncidentLevelUrgent; level++ {
		if cnt, ok := levelMap[level]; ok {
			levelDistro = append(levelDistro, coreContract.ChartTypeItem{
				Level: level,
				Label: model.IncidentLevelText[level],
				Count: cnt,
			})
		}
	}

	// Risk score calculation
	var riskScore float64
	if totalCount > 0 {
		riskScore = float64(levelMap[model.IncidentLevelUrgent]*40+levelMap[model.IncidentLevelHigh]*30+
			levelMap[model.IncidentLevelMedium]*20+levelMap[model.IncidentLevelLow]*10) / float64(totalCount)
		if overdueCount > 0 {
			riskScore += float64(overdueCount) * 5
		}
		if riskScore > 100 {
			riskScore = 100
		}
	}

	// Recent incidents (latest 10)
	var recentIncidents []model.SecurityIncident
	sess.Preload("AssetDetail").
		Where("asset_detail_id = ?", asset.Id).
		Order("created_at DESC").
		Limit(10).
		Find(&recentIncidents)

	recentItems := make([]coreContract.IncidentListItem, len(recentIncidents))
	for i, inc := range recentIncidents {
		recentItems[i] = coreContract.BuildIncidentListItem(inc, now)
	}

	// Timeline (last 12 months)
	timeline := make([]statsContract.AssetTimelineItem, 0, 12)
	for i := 11; i >= 0; i-- {
		d := now.AddDate(0, -i, 0)
		monthStart := time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.Local)
		monthEnd := monthStart.AddDate(0, 1, 0)
		var cnt int64
		sess.Model(&model.SecurityIncident{}).
			Where("asset_detail_id = ? AND created_at >= ? AND created_at < ?", asset.Id, monthStart, monthEnd).
			Count(&cnt)
		timeline = append(timeline, statsContract.AssetTimelineItem{
			Date:  monthStart.Format("2006-01"),
			Count: cnt,
		})
	}

	return &statsContract.AssetProfileResp{
		AssetName:       asset.AssetName,
		SystemName:      asset.SystemName,
		DomainIP:        asset.DomainIP,
		Unit:            asset.Unit,
		Industry:        asset.Industry,
		MLPSLevel:       asset.MLPSLevel,
		Region:          asset.Region,
		TotalIncidents:  totalCount,
		OpenIncidents:   openCount,
		ClosedIncidents: closedCount,
		OverdueCount:    overdueCount,
		LevelDistro:     levelDistro,
		RecentIncidents: recentItems,
		RiskScore:       math.Round(riskScore*100) / 100,
		Timeline:        timeline,
	}, nil
}

// ─── ListAssetSummary ───

func (s *serviceStats) ListAssetSummary(ctx context.Context, req statsContract.AssetListReq) ([]statsContract.AssetSummaryItem, int64, error) {
	sess := s.session().WithContext(ctx)

	type assetRow struct {
		AssetDetailID string  `gorm:"column:asset_detail_id"`
		AssetName     string  `gorm:"column:asset_name"`
		SystemName    string  `gorm:"column:system_name"`
		DomainIP      string  `gorm:"column:domain_ip"`
		Unit          string  `gorm:"column:unit"`
		IncidentCount int64   `gorm:"column:incident_count"`
		AvgRiskScore  float64 `gorm:"column:avg_risk_score"`
	}

	tx := sess.Model(&model.SecurityIncident{}).
		Select(`security_incidents.asset_detail_id,
			incident_assets.asset_name,
			incident_assets.system_name,
			incident_assets.domain_ip,
			incident_assets.unit,
			COUNT(*) as incident_count,
			AVG(security_incidents.risk_score) as avg_risk_score`).
		Joins("LEFT JOIN incident_assets ON incident_assets.id = security_incidents.asset_detail_id").
		Where("security_incidents.asset_detail_id != ''").
		Group("security_incidents.asset_detail_id, incident_assets.asset_name, incident_assets.system_name, incident_assets.domain_ip, incident_assets.unit")

	if req.Keyword != "" {
		tx = tx.Where("incident_assets.asset_name LIKE ? OR incident_assets.unit LIKE ?",
			"%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}

	var count int64
	countTx := sess.Table("(?) as sub", tx).Count(&count)
	if countTx.Error != nil {
		return nil, 0, countTx.Error
	}

	var rows []assetRow
	if err := tx.Order("incident_count DESC").
		Scopes(db.Paginate(req.Index, req.Size)).
		Find(&rows).Error; err != nil {
		return nil, 0, err
	}

	items := make([]statsContract.AssetSummaryItem, len(rows))
	for i, r := range rows {
		items[i] = statsContract.AssetSummaryItem{
			AssetDetailID: r.AssetDetailID,
			AssetName:     r.AssetName,
			SystemName:    r.SystemName,
			DomainIP:      r.DomainIP,
			Unit:          r.Unit,
			IncidentCount: r.IncidentCount,
			AvgRiskScore:  math.Round(r.AvgRiskScore*100) / 100,
		}
	}
	return items, count, nil
}
