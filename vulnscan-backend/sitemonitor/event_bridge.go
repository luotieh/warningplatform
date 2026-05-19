package sitemonitor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	coreContract "vulnscan-backend/incident/core/core-contract"
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type MonitorEventBridge struct {
	db          *gorm.DB
	incidentSvc coreContract.ServiceCore

	mu             sync.Mutex
	processedExecs map[string]time.Time
	dedupeWindow   time.Duration
}

func NewMonitorEventBridge(db *gorm.DB, incidentSvc coreContract.ServiceCore) *MonitorEventBridge {
	return &MonitorEventBridge{
		db:             db,
		incidentSvc:    incidentSvc,
		processedExecs: make(map[string]time.Time),
		dedupeWindow:   24 * time.Hour,
	}
}

var dimensionIncidentType = map[string]string{
	"tamper":         "网站篡改",
	"domain_hijack":  "域名劫持",
	"availability":   "可用性异常",
	"sensitive_word": "敏感词检测",
	"sensitive_file": "敏感文件泄露",
	"blacklink":      "暗链检测",
}

var dimensionLevel = map[string]int{
	"tamper":         1,
	"domain_hijack":  1,
	"availability":   2,
	"sensitive_word": 2,
	"sensitive_file": 3,
	"blacklink":      3,
}

func (b *MonitorEventBridge) OnIssueDetected(ctx context.Context, exec *model.MonitorExecution) {
	if b.incidentSvc == nil {
		return
	}
	if !exec.HasIssue || exec.Status == "failed" {
		return
	}

	cfg := ResolveIncidentConfig(ctx, b.db, exec)
	if !ShouldAutoCreateIncident(exec, cfg) {
		return
	}

	scopeID := exec.PathTaskID
	if scopeID == "" {
		scopeID = exec.TargetID
	}
	dedupeKey := fmt.Sprintf("%s:%s:%s", scopeID, exec.Dimension, exec.URL)
	if b.isDuplicate(dedupeKey) {
		return
	}

	displayName := exec.URL
	organizeID := ""
	assetID := ""
	if exec.PathTaskID != "" {
		var pt model.MonitorPathTask
		if err := b.db.Where("id = ?", exec.PathTaskID).First(&pt).Error; err == nil {
			displayName = pt.Name
			assetID = pt.AssetID
		}
	}
	if exec.TargetID != "" {
		var t model.MonitorTarget
		if err := b.db.Where("id = ?", exec.TargetID).First(&t).Error; err == nil {
			if displayName == exec.URL {
				displayName = t.Name
			}
			if assetID == "" {
				assetID = t.AssetID
			}
		}
	}

	incidentType := dimensionIncidentType[exec.Dimension]
	if incidentType == "" {
		incidentType = "监测异常"
	}

	level := dimensionLevel[exec.Dimension]
	if level == 0 {
		level = 3
	}

	name := fmt.Sprintf("[%s] %s", incidentType, displayName)

	reportTime := time.Now()
	if exec.StartedAt != nil {
		reportTime = *exec.StartedAt
	}
	discoveryTime := reportTime
	if exec.FinishedAt != nil {
		discoveryTime = *exec.FinishedAt
	}

	assetReq := coreContract.IncidentAssetReq{
		AssetName: displayName,
		DomainIP:  exec.URL,
	}
	b.enrichAssetFromID(assetID, &assetReq, &organizeID)

	req := coreContract.IncidentCreateReq{
		Name:       name,
		Level:      level,
		Source:     model.IncidentSourceSiteMonitor,
		ReportTime: reportTime,
		Asset:      assetReq,
		Metadata: coreContract.IncidentMetaReq{
			IncidentType:        incidentType,
			IncidentURL:         exec.URL,
			DiscoveryTime:       discoveryTime,
			IncidentDescription: buildMonitorIncidentDescription(exec, incidentType),
		},
	}

	if err := b.incidentSvc.CreateIncident(ctx, req, "system", organizeID); err != nil {
		slog.Error("[MonitorBridge] 创建事件失败", "error", err, "url", exec.URL, "dimension", exec.Dimension)
		return
	}

	slog.Info("[MonitorBridge] 监测问题已创建事件",
		"name", displayName, "dimension", exec.Dimension, "url", exec.URL, "level", level)
}

func (b *MonitorEventBridge) enrichAssetFromID(assetID string, asset *coreContract.IncidentAssetReq, organizeID *string) {
	if assetID == "" || b.db == nil {
		return
	}
	var a model.Asset
	if err := b.db.Where("id = ?", assetID).First(&a).Error; err != nil {
		return
	}
	if a.Name != "" {
		asset.AssetName = a.Name
		asset.SystemName = a.Name
	}
	if a.Domain != "" {
		asset.DomainIP = a.Domain
	}
	if a.IPv4 != "" {
		asset.SiteIP = a.IPv4
	}
	if a.OrganizeID != "" {
		if organizeID != nil && *organizeID == "" {
			*organizeID = a.OrganizeID
		}
		var org model.Organize
		if err := b.db.Select("name").Where("id = ?", a.OrganizeID).First(&org).Error; err == nil {
			asset.Unit = org.Name
		}
	}
}

func (b *MonitorEventBridge) isDuplicate(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	for k, t := range b.processedExecs {
		if now.Sub(t) > b.dedupeWindow {
			delete(b.processedExecs, k)
		}
	}

	if _, exists := b.processedExecs[key]; exists {
		return true
	}
	b.processedExecs[key] = now
	return false
}
