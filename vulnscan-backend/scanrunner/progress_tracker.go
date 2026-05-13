package scanrunner

import (
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
	"vulnscan-backend/scan/core"
)

type TaskProgress struct {
	TaskID         string  `json:"task_id"`
	Status         string  `json:"status"`
	CurrentStage   string  `json:"current_stage"`
	CurrentModule  string  `json:"current_module"`
	Progress       float64 `json:"progress"`
	TotalTargets   int     `json:"total_targets"`
	ScannedTargets int     `json:"scanned_targets"`
	FindingCount   int     `json:"finding_count"`
	VulnCritical   int     `json:"vuln_critical"`
	VulnHigh       int     `json:"vuln_high"`
	VulnMedium     int     `json:"vuln_medium"`
	VulnLow        int     `json:"vuln_low"`
	VulnInfo       int     `json:"vuln_info"`
	AliveHosts     int     `json:"alive_hosts"`
	OpenPorts      int     `json:"open_ports"`
	Duration       string  `json:"duration"`
	StagesTotal    int     `json:"stages_total"`
	StagesDone     int     `json:"stages_done"`
}

type ProgressTracker struct {
	db     *gorm.DB
	taskID string

	mu            sync.RWMutex
	currentStage  string
	currentModule string
	stagesTotal   int
	stagesDone    int
	modulesTotal  int
	modulesDone   atomic.Int64
	scanned       atomic.Int64
	findings      []*core.Finding
	startTime     time.Time
	totalTargets  int
}

func NewProgressTracker(db *gorm.DB, taskID string, totalTargets int) *ProgressTracker {
	return &ProgressTracker{
		db:           db,
		taskID:       taskID,
		startTime:    time.Now(),
		totalTargets: totalTargets,
	}
}

func (pt *ProgressTracker) SetStages(total int) {
	pt.mu.Lock()
	pt.stagesTotal = total
	pt.mu.Unlock()
}

func (pt *ProgressTracker) SetModulesTotal(total int) {
	pt.mu.Lock()
	pt.modulesTotal = total
	pt.mu.Unlock()
}

func (pt *ProgressTracker) SetCurrentStage(name string) {
	pt.mu.Lock()
	pt.currentStage = name
	pt.mu.Unlock()
}

func (pt *ProgressTracker) SetCurrentModule(name string) {
	pt.mu.Lock()
	pt.currentModule = name
	pt.mu.Unlock()
}

func (pt *ProgressTracker) IncrementModuleDone() {
	pt.modulesDone.Add(1)
}

func (pt *ProgressTracker) SetScanned(n int) {
	pt.scanned.Store(int64(n))
}

func (pt *ProgressTracker) IncrementStageDone() {
	pt.mu.Lock()
	pt.stagesDone++
	pt.mu.Unlock()
}

func (pt *ProgressTracker) AppendFindings(findings []*core.Finding) {
	pt.mu.Lock()
	pt.findings = append(pt.findings, findings...)
	pt.mu.Unlock()
}

func (pt *ProgressTracker) GetFindings() []*core.Finding {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	out := make([]*core.Finding, len(pt.findings))
	copy(out, pt.findings)
	return out
}

func (pt *ProgressTracker) Get() *TaskProgress {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	scanned := int(pt.scanned.Load())
	done := int(pt.modulesDone.Load())

	progress := float64(0)
	if pt.modulesTotal > 0 {
		progress = float64(done) / float64(pt.modulesTotal) * 100
		if progress > 99 && done < pt.modulesTotal {
			progress = 99
		}
	}

	p := &TaskProgress{
		TaskID:         pt.taskID,
		Status:         model.TaskStatusRunning,
		CurrentStage:   pt.currentStage,
		CurrentModule:  pt.currentModule,
		Progress:       progress,
		TotalTargets:   pt.totalTargets,
		ScannedTargets: scanned,
		FindingCount:   len(pt.findings),
		Duration:       time.Since(pt.startTime).Round(time.Millisecond).String(),
		StagesTotal:    pt.stagesTotal,
		StagesDone:     pt.stagesDone,
	}

	for _, f := range pt.findings {
		switch f.Type {
		case "host_alive":
			p.AliveHosts++
		case "port_open", "udp_port":
			p.OpenPorts++
		}

		if isReconFinding(f) {
			continue
		}
		switch f.Severity {
		case "critical":
			p.VulnCritical++
		case "high":
			p.VulnHigh++
		case "medium":
			p.VulnMedium++
		case "low":
			p.VulnLow++
		case "info":
			p.VulnInfo++
		}
	}

	return p
}

func (pt *ProgressTracker) SyncToDB(stage string) {
	p := pt.Get()
	pt.db.Model(&model.ScanTask{}).Where("id = ?", pt.taskID).
		Updates(map[string]interface{}{
			"progress":        p.Progress,
			"current_stage":   stage,
			"current_module":  p.CurrentModule,
			"scanned_targets": p.ScannedTargets,
			"alive_hosts":     p.AliveHosts,
			"open_ports":      p.OpenPorts,
			"vuln_critical":   p.VulnCritical,
			"vuln_high":       p.VulnHigh,
			"vuln_medium":     p.VulnMedium,
			"vuln_low":        p.VulnLow,
			"vuln_info":       p.VulnInfo,
		})
}

func (pt *ProgressTracker) FinishTask(status, errMsg string) {
	now := time.Now()
	p := pt.Get()

	updates := map[string]interface{}{
		"status":          status,
		"finished_at":     &now,
		"progress":        100,
		"scanned_targets": p.ScannedTargets,
		"vuln_critical":   p.VulnCritical,
		"vuln_high":       p.VulnHigh,
		"vuln_medium":     p.VulnMedium,
		"vuln_low":        p.VulnLow,
		"vuln_info":       p.VulnInfo,
		"alive_hosts":     p.AliveHosts,
		"open_ports":      p.OpenPorts,
	}

	if status != model.TaskStatusCompleted {
		updates["progress"] = p.Progress
	}
	if errMsg != "" {
		updates["error_msg"] = errMsg
	}

	pt.db.Model(&model.ScanTask{}).Where("id = ?", pt.taskID).Updates(updates)
}
