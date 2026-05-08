package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	transferContract "vulnscan-backend/circular/transfer/transfer-contract"
	coreContract "vulnscan-backend/incident/core/core-contract"
	"vulnscan-backend/model"
)

// EventBridge connects scan findings to incident creation and incident to circular transfer.
type EventBridge struct {
	db             *gorm.DB
	incidentSvc    coreContract.ServiceCore
	transferSvc    transferContract.ServiceTransfer
	config         EventBridgeConfig
	mu             sync.Mutex
	processedTasks map[string]time.Time
}

type EventBridgeConfig struct {
	Enabled                  bool
	AutoCreateIncident       bool
	AutoTransferToCircular   bool
	MinSeverityForIncident   string // "critical", "high", "medium"
	MinConfidenceForIncident int    // minimum confidence to auto-create (0-100)
	DeduplicateWindow        time.Duration
}

func DefaultEventBridgeConfig() EventBridgeConfig {
	return EventBridgeConfig{
		Enabled:                  true,
		AutoCreateIncident:       true,
		AutoTransferToCircular:   true,
		MinSeverityForIncident:   "high",
		MinConfidenceForIncident: 70,
		DeduplicateWindow:        24 * time.Hour,
	}
}

func NewEventBridge(db *gorm.DB, incidentSvc coreContract.ServiceCore, transferSvc transferContract.ServiceTransfer, config EventBridgeConfig) *EventBridge {
	return &EventBridge{
		db:             db,
		incidentSvc:    incidentSvc,
		transferSvc:    transferSvc,
		config:         config,
		processedTasks: make(map[string]time.Time),
	}
}

// OnScanComplete is called after a scan task finishes. It reviews vuln findings
// and creates incidents for high-severity ones.
func (eb *EventBridge) OnScanComplete(ctx context.Context, taskID string) {
	if !eb.config.Enabled || !eb.config.AutoCreateIncident {
		return
	}
	if eb.incidentSvc == nil {
		return
	}

	eb.mu.Lock()
	if t, ok := eb.processedTasks[taskID]; ok && time.Since(t) < eb.config.DeduplicateWindow {
		eb.mu.Unlock()
		return
	}
	eb.processedTasks[taskID] = time.Now()
	eb.mu.Unlock()

	eb.cleanupProcessedTasks()

	var findings []model.ScanFinding
	query := eb.db.WithContext(ctx).
		Where("task_id = ? AND category = ?", taskID, model.FindingCategoryVuln).
		Where("severity IN ?", eb.eligibleSeverities())

	if eb.config.MinConfidenceForIncident > 0 {
		query = query.Where("confidence >= ?", eb.config.MinConfidenceForIncident)
	}

	if err := query.Find(&findings).Error; err != nil {
		slog.Warn("[EventBridge] 查询扫描发现失败", "task_id", taskID, "error", err)
		return
	}

	if len(findings) == 0 {
		return
	}

	created := 0
	for _, f := range findings {
		if eb.incidentAlreadyExists(ctx, taskID, f) {
			continue
		}

		if err := eb.createIncidentFromFinding(ctx, f); err != nil {
			slog.Warn("[EventBridge] 自动创建事件失败", "finding_id", f.ID, "error", err)
			continue
		}
		created++
	}

	if created > 0 {
		slog.Info("[EventBridge] 扫描发现自动创建安全事件",
			"task_id", taskID, "findings", len(findings), "incidents_created", created)
	}
}

// OnIncidentReviewPassed is called when an incident passes review.
// It automatically transfers the incident to the circular system.
func (eb *EventBridge) OnIncidentReviewPassed(ctx context.Context, incident model.SecurityIncident) {
	if !eb.config.Enabled || !eb.config.AutoTransferToCircular {
		return
	}
	if eb.transferSvc == nil {
		return
	}

	if incident.Level < model.IncidentLevelHigh {
		return
	}

	var asset model.IncidentAsset
	eb.db.WithContext(ctx).Where("id = ?", incident.AssetDetailID).First(&asset)

	var metadata model.IncidentMetadata
	eb.db.WithContext(ctx).Where("id = ?", incident.EventMetadataID).First(&metadata)

	req := transferContract.TransferIncidentReq{
		IncidentNo:   incident.IncidentNo,
		Name:         incident.Name,
		Level:        incident.Level,
		AiOpinion:    incident.AiOpinion,
		AiConfidence: incident.AiConfidence,
		SourceSystem: model.IncidentSourceSystemLocal,
		AssetInfo: &transferContract.TransferAssetInfo{
			AssetName:    asset.AssetName,
			SystemName:   asset.SystemName,
			DomainIP:     asset.DomainIP,
			SiteIP:       asset.SiteIP,
			Unit:         asset.Unit,
			UnitType:     asset.UnitType,
			Industry:     asset.Industry,
			MLPSRecordNo: asset.MLPSRecordNo,
			MLPSLevel:    asset.MLPSLevel,
			Region:       asset.Region,
		},
		MetadataInfo: &transferContract.TransferMetadataInfo{
			DataNo:              metadata.DataNo,
			IncidentType:        metadata.IncidentType,
			IncidentURL:         metadata.IncidentURL,
			IncidentDescription: metadata.IncidentDescription,
			CvssScore:           metadata.CvssScore,
			CveId:               metadata.CveId,
		},
	}

	circularCode, err := eb.transferSvc.ReceiveIncident(ctx, req, "system")
	if err != nil {
		slog.Warn("[EventBridge] 事件流转通报失败",
			"incident_no", incident.IncidentNo, "error", err)
		return
	}

	oplog := model.BuildIncidentOperationLog(
		incident.Id, incident.IncidentNo, model.IncidentOpTransfer,
		"system", "系统自动", "流转到通报系统成功",
		map[string]interface{}{"circular_code": circularCode},
		model.IncidentSourceSystemLocal,
	)
	model.CreateIncidentOperationLog(eb.db.WithContext(ctx), oplog)

	slog.Info("[EventBridge] 事件自动流转到通报系统",
		"incident_no", incident.IncidentNo, "circular_code", circularCode)
}

func (eb *EventBridge) createIncidentFromFinding(ctx context.Context, f model.ScanFinding) error {
	level := severityToIncidentLevel(f.Severity)

	name := f.Title
	if len(name) > 100 {
		name = name[:100]
	}

	var discoveryTime time.Time
	if !f.CreatedAt.IsZero() {
		discoveryTime = f.CreatedAt
	} else {
		discoveryTime = time.Now()
	}

	cveId := ""
	cvssScore := 0.0
	incidentURL := ""
	incidentType := "漏洞"

	if f.Data != nil {
		if v, ok := f.Data["cve_id"].(string); ok {
			cveId = v
		}
		if v, ok := f.Data["cvss_score"].(string); ok {
			fmt.Sscanf(v, "%f", &cvssScore)
		}
		if v, ok := f.Data["matched_at"].(string); ok {
			incidentURL = v
		}
		if v, ok := f.Data["template_id"].(string); ok && incidentType == "漏洞" {
			if strings.Contains(v, "xss") {
				incidentType = "XSS漏洞"
			} else if strings.Contains(v, "sqli") || strings.Contains(v, "sql-injection") {
				incidentType = "SQL注入"
			} else if strings.Contains(v, "rce") || strings.Contains(v, "command") {
				incidentType = "远程代码执行"
			}
		}
	}

	req := coreContract.IncidentCreateReq{
		Name:       name,
		Level:      level,
		Source:     model.IncidentSourceVulnScan,
		ReportTime: discoveryTime,
		Asset: coreContract.IncidentAssetReq{
			DomainIP: f.Target,
		},
		Metadata: coreContract.IncidentMetaReq{
			IncidentType:        incidentType,
			IncidentURL:         incidentURL,
			DiscoveryTime:       discoveryTime,
			IncidentDescription: f.Description,
			CvssScore:           cvssScore,
			CveId:               cveId,
		},
	}

	if f.AssetID != "" {
		var asset model.Asset
		if err := eb.db.WithContext(ctx).Where("id = ?", f.AssetID).First(&asset).Error; err == nil {
			req.Asset.AssetName = asset.Name
			req.Asset.SystemName = asset.SystemName
			if asset.Domain != "" {
				req.Asset.DomainIP = asset.Domain
			}
			if asset.IPv4 != "" {
				req.Asset.SiteIP = asset.IPv4
			}
		}
	}

	return eb.incidentSvc.CreateIncident(ctx, req, "system")
}

func (eb *EventBridge) incidentAlreadyExists(ctx context.Context, taskID string, f model.ScanFinding) bool {
	dedupName := f.Title
	if len(dedupName) > 100 {
		dedupName = dedupName[:100]
	}

	var count int64
	eb.db.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("name = ? AND source = ?", dedupName, model.IncidentSourceVulnScan).
		Where("created_at > ?", time.Now().Add(-eb.config.DeduplicateWindow)).
		Count(&count)
	return count > 0
}

func (eb *EventBridge) eligibleSeverities() []string {
	switch eb.config.MinSeverityForIncident {
	case "critical":
		return []string{"critical"}
	case "high":
		return []string{"critical", "high"}
	case "medium":
		return []string{"critical", "high", "medium"}
	default:
		return []string{"critical", "high"}
	}
}

func (eb *EventBridge) cleanupProcessedTasks() {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	for k, t := range eb.processedTasks {
		if time.Since(t) > eb.config.DeduplicateWindow {
			delete(eb.processedTasks, k)
		}
	}
}

func severityToIncidentLevel(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return model.IncidentLevelUrgent
	case "high":
		return model.IncidentLevelHigh
	case "medium":
		return model.IncidentLevelMedium
	default:
		return model.IncidentLevelLow
	}
}
