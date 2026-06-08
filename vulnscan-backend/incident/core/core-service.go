package core

import (
	"context"
	"fmt"
	"time"
	"vulnscan-backend/model"

	coreContract "vulnscan-backend/incident/core/core-contract"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

type serviceCore struct {
	db *db.DB
}

func NewServiceCore(database *db.DB) *serviceCore {
	return &serviceCore{db: database}
}

func (s *serviceCore) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceCore) CreateIncident(ctx context.Context, req coreContract.IncidentCreateReq, createdBy string, organizeID string) error {
	sess := s.session()
	now := time.Now()

	assetId := ulid.GenerateID()
	asset := model.IncidentAsset{
		FullModel: model.FullModel{
			Id:        assetId,
			CreatedAt: now,
			CreatedBy: createdBy,
			UpdatedAt: now,
			UpdatedBy: createdBy,
		},
		AssetName:    req.Asset.AssetName,
		SystemName:   req.Asset.SystemName,
		DomainIP:     req.Asset.DomainIP,
		SiteIP:       req.Asset.SiteIP,
		Unit:         req.Asset.Unit,
		UnitType:     req.Asset.UnitType,
		Industry:     req.Asset.Industry,
		MLPSRecordNo: req.Asset.MLPSRecordNo,
		MLPSLevel:    req.Asset.MLPSLevel,
		MIITRecordNo: req.Asset.MIITRecordNo,
		Region:       req.Asset.Region,
	}

	metaId := ulid.GenerateID()
	metadata := model.IncidentMetadata{
		FullModel: model.FullModel{
			Id:        metaId,
			CreatedAt: now,
			CreatedBy: createdBy,
			UpdatedAt: now,
			UpdatedBy: createdBy,
		},
		DataNo:              req.Metadata.DataNo,
		IncidentType:        req.Metadata.IncidentType,
		IncidentURL:         req.Metadata.IncidentURL,
		DiscoveryTime:       req.Metadata.DiscoveryTime,
		VendorRegion:        req.Metadata.VendorRegion,
		IncidentDescription: req.Metadata.IncidentDescription,
		VendorName:          req.Metadata.VendorName,
		VendorTime:          req.Metadata.VendorTime,
		AffectedCount:       req.Metadata.AffectedCount,
		AffectedType:        req.Metadata.AffectedType,
		CvssScore:           req.Metadata.CvssScore,
		CveId:               req.Metadata.CveId,
		OwaspCategory:       req.Metadata.OwaspCategory,
		ExploitDifficulty:   req.Metadata.ExploitDifficulty,
		AffectScope:         req.Metadata.AffectScope,
	}

	incidentId := ulid.GenerateID()
	incidentNo := coreContract.GenerateIncidentNo()
	slaLevel := model.IncidentAutoSLALevel(req.Level)
	slaHours := model.IncidentSLAHours(slaLevel)
	var slaDeadline *time.Time
	if slaHours > 0 {
		dl := now.Add(time.Duration(slaHours) * time.Hour)
		slaDeadline = &dl
	}

	reportTime := req.ReportTime
	if reportTime.IsZero() {
		reportTime = now
	}

	incident := model.SecurityIncident{
		FullModel: model.FullModel{
			Id:        incidentId,
			CreatedAt: now,
			CreatedBy: createdBy,
			UpdatedAt: now,
			UpdatedBy: createdBy,
		},
		IncidentNo:      incidentNo,
		Name:            req.Name,
		Level:           req.Level,
		Source:          req.Source,
		Status:          model.IncidentStatusPendingReview,
		OrganizeID:      organizeID,
		ReportTime:      reportTime,
		AssetDetailID:   assetId,
		EventMetadataID: metaId,
		SLALevel:        slaLevel,
		SLADeadline:     slaDeadline,
	}

	return sess.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&asset).Error; err != nil {
			return fmt.Errorf("创建资产记录失败: %w", err)
		}
		if err := tx.Create(&metadata).Error; err != nil {
			return fmt.Errorf("创建元数据记录失败: %w", err)
		}
		if err := tx.Create(&incident).Error; err != nil {
			return fmt.Errorf("创建事件记录失败: %w", err)
		}

		oplog := model.BuildIncidentOperationLog(
			incidentId, incidentNo, model.IncidentOpInput,
			createdBy, "", "录入成功",
			map[string]interface{}{"name": req.Name, "level": req.Level},
			model.IncidentSourceSystemLocal,
		)
		return model.CreateIncidentOperationLog(tx, oplog)
	})
}

func (s *serviceCore) UpdateIncident(ctx context.Context, id string, req coreContract.IncidentUpdateReq) error {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).Where("id = ?", id).First(&incident).Error; err != nil {
		return fmt.Errorf("事件不存在")
	}

	return sess.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		incidentUpdates := make(map[string]interface{})
		if req.Name != "" {
			incidentUpdates["name"] = req.Name
		}
		if req.Level != nil {
			incidentUpdates["level"] = *req.Level
		}
		if req.Source != nil {
			incidentUpdates["source"] = *req.Source
		}

		if len(incidentUpdates) > 0 {
			if err := tx.Model(&model.SecurityIncident{}).Where("id = ?", id).Updates(incidentUpdates).Error; err != nil {
				return fmt.Errorf("更新事件失败: %w", err)
			}
		}

		if req.Asset != nil && incident.AssetDetailID != "" {
			assetUpdates := coreContract.AssetReqToMap(*req.Asset)
			if len(assetUpdates) > 0 {
				if err := tx.Model(&model.IncidentAsset{}).Where("id = ?", incident.AssetDetailID).Updates(assetUpdates).Error; err != nil {
					return fmt.Errorf("更新资产信息失败: %w", err)
				}
			}
		}

		if req.Metadata != nil && incident.EventMetadataID != "" {
			metaUpdates := buildMetadataUpdateMap(*req.Metadata)
			if len(metaUpdates) > 0 {
				if err := tx.Model(&model.IncidentMetadata{}).Where("id = ?", incident.EventMetadataID).Updates(metaUpdates).Error; err != nil {
					return fmt.Errorf("更新元数据失败: %w", err)
				}
			}
		}

		return nil
	})
}

func (s *serviceCore) DeleteIncident(ctx context.Context, id string) error {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).Where("id = ?", id).First(&incident).Error; err != nil {
		return fmt.Errorf("事件不存在")
	}
	if incident.Status == model.IncidentStatusReviewPassed {
		return fmt.Errorf("复核通过的事件不允许删除")
	}

	return sess.WithContext(ctx).Where("id = ?", id).Delete(&model.SecurityIncident{}).Error
}

func (s *serviceCore) GetIncidentDetail(ctx context.Context, id string) (*coreContract.IncidentDetailResp, error) {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).
		Preload("AssetDetail").
		Preload("EventMetadata").
		Where("id = ?", id).
		First(&incident).Error; err != nil {
		return nil, fmt.Errorf("事件不存在")
	}

	var logs []model.IncidentOperationLog
	sess.WithContext(ctx).
		Where("incident_id = ?", id).
		Order("operation_time DESC").
		Find(&logs)

	oplogItems := make([]coreContract.OplogItem, 0, len(logs))
	for _, log := range logs {
		oplogItems = append(oplogItems, coreContract.ToOplogItem(log))
	}

	return &coreContract.IncidentDetailResp{
		SecurityIncident: incident,
		CurrentStep:      model.IncidentCurrentStep(incident.Status, incident.AiPreStatus),
		OperationLogs:    oplogItems,
	}, nil
}

func (s *serviceCore) ListIncidents(ctx context.Context, req coreContract.IncidentListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]coreContract.IncidentListItem, int64, error) {
	sess := s.session()
	now := time.Now()

	tx := sess.WithContext(ctx).Model(&model.SecurityIncident{}).Scopes(scopes...).
		Joins("LEFT JOIN incident_assets ON incident_assets.id = security_incidents.asset_detail_id")

	if req.Name != "" {
		tx = tx.Where("security_incidents.name LIKE ?", "%"+req.Name+"%")
	}
	if req.AssetName != "" {
		tx = tx.Where("incident_assets.asset_name LIKE ?", "%"+req.AssetName+"%")
	}
	if req.Unit != "" {
		tx = tx.Where("incident_assets.unit LIKE ?", "%"+req.Unit+"%")
	}
	if req.Level != nil {
		tx = tx.Where("security_incidents.level = ?", *req.Level)
	}
	if req.Status != nil {
		tx = tx.Where("security_incidents.status = ?", *req.Status)
	}

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	var incidents []model.SecurityIncident
	if err := tx.
		Preload("AssetDetail").
		Select("security_incidents.*").
		Scopes(db.Paginate(req.Index, req.Size)).
		Order("security_incidents.status ASC, security_incidents.created_at DESC").
		Find(&incidents).Error; err != nil {
		return nil, 0, err
	}

	items := make([]coreContract.IncidentListItem, 0, len(incidents))
	for _, inc := range incidents {
		items = append(items, coreContract.BuildIncidentListItem(inc, now))
	}

	return items, count, nil
}

func (s *serviceCore) GetDashboardStats(ctx context.Context) (*coreContract.DashboardStatsResp, error) {
	sess := s.session()
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	stats := &coreContract.DashboardStatsResp{}

	sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("created_at >= ?", todayStart).
		Count(&stats.TodayTotal)

	sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("level = ?", model.IncidentLevelUrgent).
		Where("status != ?", model.IncidentStatusClosed).
		Count(&stats.UrgentCount)

	sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("status IN ?", []int{model.IncidentStatusRemediation, model.IncidentStatusRemediating}).
		Count(&stats.DispatchCount)

	sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("status = ?", model.IncidentStatusPendingReview).
		Count(&stats.PendingAudit)

	sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("status = ?", model.IncidentStatusRemediating).
		Count(&stats.RemediatingCnt)

	sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("remediation_deadline < ? AND status NOT IN ?", now, []int{model.IncidentStatusClosed, model.IncidentStatusVerifying}).
		Count(&stats.OverdueCnt)

	sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("status = ?", model.IncidentStatusClosed).
		Count(&stats.ClosedCnt)

	var totalCount int64
	sess.WithContext(ctx).Model(&model.SecurityIncident{}).Count(&totalCount)
	if totalCount > 0 {
		stats.RemediationRate = float64(stats.ClosedCnt) / float64(totalCount) * 100
	}

	stats.Total = totalCount
	var remediationPending int64
	sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("status = ?", model.IncidentStatusRemediation).
		Count(&remediationPending)
	stats.InRemediation = remediationPending + stats.RemediatingCnt
	stats.Closed = stats.ClosedCnt
	stats.Overdue = stats.OverdueCnt

	return stats, nil
}

func (s *serviceCore) GetChartByType(ctx context.Context) ([]coreContract.ChartTypeItem, error) {
	sess := s.session()

	type typeCount struct {
		IncidentType string `gorm:"column:incident_type"`
		Count        int64  `gorm:"column:count"`
	}
	var results []typeCount
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Select(`CASE
			WHEN incident_metadata.incident_type IS NULL OR incident_metadata.incident_type = '' THEN '未分类'
			ELSE incident_metadata.incident_type
		END AS incident_type, COUNT(*) AS count`).
		Joins("LEFT JOIN incident_metadata ON incident_metadata.id = security_incidents.event_metadata_id").
		Group("incident_type").
		Order("count DESC").
		Scan(&results).Error; err != nil {
		return nil, err
	}

	var total int64
	for _, r := range results {
		total += r.Count
	}

	items := make([]coreContract.ChartTypeItem, 0, len(results))
	for _, r := range results {
		item := coreContract.ChartTypeItem{
			Type:  r.IncidentType,
			Count: r.Count,
		}
		if total > 0 {
			item.Percentage = fmt.Sprintf("%.1f%%", float64(r.Count)/float64(total)*100)
		} else {
			item.Percentage = "0%"
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *serviceCore) GetChartByLevel(ctx context.Context) ([]coreContract.ChartLevelItem, error) {
	sess := s.session()

	type levelCount struct {
		Level int   `json:"level"`
		Count int64 `json:"count"`
	}
	var results []levelCount
	sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Select("level, COUNT(*) as count").
		Group("level").
		Find(&results)

	countMap := make(map[int]int64)
	var total int64
	for _, r := range results {
		countMap[r.Level] = r.Count
		total += r.Count
	}

	levels := []int{
		model.IncidentLevelLow,
		model.IncidentLevelMedium,
		model.IncidentLevelHigh,
		model.IncidentLevelUrgent,
	}
	items := make([]coreContract.ChartLevelItem, 0, len(levels))
	for _, lv := range levels {
		cnt := countMap[lv]
		item := coreContract.ChartLevelItem{
			Level: lv,
			Label: model.IncidentLevelText[lv],
			Count: cnt,
		}
		if total > 0 {
			item.Percentage = fmt.Sprintf("%.1f%%", float64(cnt)/float64(total)*100)
		} else {
			item.Percentage = "0%"
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *serviceCore) GetChartByTrend(ctx context.Context, rangeType string) ([]coreContract.ChartTrendItem, error) {
	sess := s.session()
	now := time.Now()
	loc := now.Location()

	days := 7
	if rangeType == "month" {
		days = 30
	}

	items := make([]coreContract.ChartTrendItem, 0, days)
	for i := days - 1; i >= 0; i-- {
		day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, -i)
		dayEnd := day.Add(24 * time.Hour)
		period := day.Format("01-02")

		var created, closed, pending int64
		sess.WithContext(ctx).Model(&model.SecurityIncident{}).
			Where("created_at >= ? AND created_at < ?", day, dayEnd).
			Count(&created)
		sess.WithContext(ctx).Model(&model.SecurityIncident{}).
			Where("closed_at IS NOT NULL AND closed_at >= ? AND closed_at < ?", day, dayEnd).
			Count(&closed)
		sess.WithContext(ctx).Model(&model.SecurityIncident{}).
			Where("created_at < ?", dayEnd).
			Where("closed_at IS NULL OR closed_at >= ?", dayEnd).
			Count(&pending)

		items = append(items, coreContract.ChartTrendItem{
			Period:  period,
			Date:    day.Format("2006-01-02"),
			Created: created,
			Closed:  closed,
			Pending: pending,
			Count:   created,
		})
	}

	return items, nil
}

func (s *serviceCore) GetOplogsByIncidentId(ctx context.Context, incidentId string) ([]coreContract.OplogItem, error) {
	sess := s.session()

	var logs []model.IncidentOperationLog
	if err := sess.WithContext(ctx).
		Where("incident_id = ?", incidentId).
		Order("operation_time DESC").
		Find(&logs).Error; err != nil {
		return nil, err
	}

	items := make([]coreContract.OplogItem, 0, len(logs))
	for _, log := range logs {
		items = append(items, coreContract.ToOplogItem(log))
	}
	return items, nil
}

func (s *serviceCore) GetOplogsByIncidentNo(ctx context.Context, incidentNo string) ([]coreContract.OplogItem, error) {
	sess := s.session()

	var logs []model.IncidentOperationLog
	if err := sess.WithContext(ctx).
		Where("incident_no = ?", incidentNo).
		Order("operation_time DESC").
		Find(&logs).Error; err != nil {
		return nil, err
	}

	items := make([]coreContract.OplogItem, 0, len(logs))
	for _, log := range logs {
		items = append(items, coreContract.ToOplogItem(log))
	}
	return items, nil
}

func (s *serviceCore) ReceiveCallbackOplog(ctx context.Context, req coreContract.OplogCallbackReq) error {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).Where("incident_no = ?", req.IncidentNo).First(&incident).Error; err != nil {
		return fmt.Errorf("事件不存在: %s", req.IncidentNo)
	}

	opTime := req.OperationTime
	if opTime.IsZero() {
		opTime = time.Now()
	}

	detailMap := req.Detail
	if detailMap == nil {
		detailMap = make(map[string]interface{})
	}
	if req.CircularCode != "" {
		detailMap["circular_code"] = req.CircularCode
	}

	oplog := model.BuildIncidentOperationLogWithTime(
		incident.Id,
		incident.IncidentNo,
		req.OperationType,
		req.OperatorId,
		req.OperatorName,
		req.Result,
		detailMap,
		model.IncidentSourceSystemCircular,
		opTime,
	)

	return model.CreateIncidentOperationLog(sess.WithContext(ctx), oplog)
}

// buildMetadataUpdateMap converts non-empty metadata fields to a GORM update map.
func buildMetadataUpdateMap(m coreContract.IncidentMetaReq) map[string]interface{} {
	updates := make(map[string]interface{})
	if m.DataNo != "" {
		updates["data_no"] = m.DataNo
	}
	if m.IncidentType != "" {
		updates["incident_type"] = m.IncidentType
	}
	if m.IncidentURL != "" {
		updates["incident_url"] = m.IncidentURL
	}
	if !m.DiscoveryTime.IsZero() {
		updates["discovery_time"] = m.DiscoveryTime
	}
	if m.VendorRegion != "" {
		updates["vendor_region"] = m.VendorRegion
	}
	if m.IncidentDescription != "" {
		updates["incident_description"] = m.IncidentDescription
	}
	if m.VendorName != "" {
		updates["vendor_name"] = m.VendorName
	}
	if !m.VendorTime.IsZero() {
		updates["vendor_time"] = m.VendorTime
	}
	if m.AffectedCount != "" {
		updates["affected_count"] = m.AffectedCount
	}
	if m.AffectedType != "" {
		updates["affected_type"] = m.AffectedType
	}
	if m.CvssScore != 0 {
		updates["cvss_score"] = m.CvssScore
	}
	if m.CveId != "" {
		updates["cve_id"] = m.CveId
	}
	if m.OwaspCategory != "" {
		updates["owasp_category"] = m.OwaspCategory
	}
	if m.ExploitDifficulty != "" {
		updates["exploit_difficulty"] = m.ExploitDifficulty
	}
	if m.AffectScope != "" {
		updates["affect_scope"] = m.AffectScope
	}
	return updates
}
