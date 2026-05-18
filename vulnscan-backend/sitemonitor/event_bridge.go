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

	dedupeKey := fmt.Sprintf("%s:%s:%s", exec.TaskID, exec.Dimension, exec.URL)
	if b.isDuplicate(dedupeKey) {
		return
	}

	var task model.MonitorTask
	if err := b.db.Where("id = ?", exec.TaskID).First(&task).Error; err != nil {
		slog.Warn("[MonitorBridge] 任务不存在", "task_id", exec.TaskID)
		return
	}

	incidentType := dimensionIncidentType[exec.Dimension]
	if incidentType == "" {
		incidentType = "监测异常"
	}

	level := dimensionLevel[exec.Dimension]
	if level == 0 {
		level = 3
	}

	name := fmt.Sprintf("[%s] %s", incidentType, task.TaskName)
	if exec.URL != "" {
		name = fmt.Sprintf("[%s] %s", incidentType, exec.URL)
	}

	req := coreContract.IncidentCreateReq{
		Name:       name,
		Level:      level,
		Source:     2,
		ReportTime: time.Now(),
		Asset: coreContract.IncidentAssetReq{
			AssetName: task.TaskName,
			DomainIP:  exec.URL,
		},
		Metadata: coreContract.IncidentMetaReq{
			IncidentType:        incidentType,
			IncidentURL:         exec.URL,
			DiscoveryTime:       time.Now(),
			IncidentDescription: fmt.Sprintf("站点监测发现%s问题，维度: %s，目标: %s", incidentType, exec.Dimension, exec.URL),
		},
	}

	if err := b.incidentSvc.CreateIncident(ctx, req, "system", task.OrganizeID); err != nil {
		slog.Error("[MonitorBridge] 创建事件失败", "error", err, "url", exec.URL, "dimension", exec.Dimension)
		return
	}

	slog.Info("[MonitorBridge] 监测问题已创建事件",
		"task", task.TaskName, "dimension", exec.Dimension, "url", exec.URL, "level", level)
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
