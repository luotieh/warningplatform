package engine

import (
	"sync"
	"sync/atomic"
	"time"
)

// ScanMetrics collects per-module and global scan statistics.
type ScanMetrics struct {
	mu      sync.RWMutex
	modules map[string]*ModuleMetrics
	global  GlobalMetrics
}

type ModuleMetrics struct {
	Invocations   atomic.Int64
	Successes     atomic.Int64
	Failures      atomic.Int64
	TotalDuration atomic.Int64
	FindingCount  atomic.Int64
}

type GlobalMetrics struct {
	TotalTargets   atomic.Int64
	ScannedTargets atomic.Int64
	TotalFindings  atomic.Int64
	StartTime      time.Time
}

var scanMetrics *ScanMetrics
var metricsOnce sync.Once

func GetScanMetrics() *ScanMetrics {
	metricsOnce.Do(func() {
		scanMetrics = &ScanMetrics{
			modules: make(map[string]*ModuleMetrics),
			global: GlobalMetrics{
				StartTime: time.Now(),
			},
		}
	})
	return scanMetrics
}

func (sm *ScanMetrics) GetModule(moduleID string) *ModuleMetrics {
	sm.mu.RLock()
	m, ok := sm.modules[moduleID]
	sm.mu.RUnlock()
	if ok {
		return m
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	if m, ok = sm.modules[moduleID]; ok {
		return m
	}
	m = &ModuleMetrics{}
	sm.modules[moduleID] = m
	return m
}

func (sm *ScanMetrics) RecordModuleRun(moduleID string, success bool, duration time.Duration, findings int) {
	m := sm.GetModule(moduleID)
	m.Invocations.Add(1)
	if success {
		m.Successes.Add(1)
	} else {
		m.Failures.Add(1)
	}
	m.TotalDuration.Add(duration.Milliseconds())
	m.FindingCount.Add(int64(findings))

	sm.global.TotalFindings.Add(int64(findings))
}

func (sm *ScanMetrics) RecordTargetScanned() {
	sm.global.ScannedTargets.Add(1)
}

func (sm *ScanMetrics) SetTotalTargets(n int64) {
	sm.global.TotalTargets.Store(n)
}

// Snapshot returns a point-in-time snapshot of all metrics.
type MetricsSnapshot struct {
	Uptime         string                    `json:"uptime"`
	TotalTargets   int64                     `json:"total_targets"`
	ScannedTargets int64                     `json:"scanned_targets"`
	TotalFindings  int64                     `json:"total_findings"`
	Modules        map[string]ModuleSnapshot `json:"modules"`
}

type ModuleSnapshot struct {
	Invocations int64   `json:"invocations"`
	Successes   int64   `json:"successes"`
	Failures    int64   `json:"failures"`
	AvgDuration float64 `json:"avg_duration_ms"`
	Findings    int64   `json:"findings"`
	SuccessRate float64 `json:"success_rate"`
}

func (sm *ScanMetrics) Snapshot() MetricsSnapshot {
	snap := MetricsSnapshot{
		Uptime:         time.Since(sm.global.StartTime).Round(time.Second).String(),
		TotalTargets:   sm.global.TotalTargets.Load(),
		ScannedTargets: sm.global.ScannedTargets.Load(),
		TotalFindings:  sm.global.TotalFindings.Load(),
		Modules:        make(map[string]ModuleSnapshot),
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for id, m := range sm.modules {
		invocations := m.Invocations.Load()
		successes := m.Successes.Load()
		totalDur := m.TotalDuration.Load()

		var avgDur float64
		if invocations > 0 {
			avgDur = float64(totalDur) / float64(invocations)
		}
		var successRate float64
		if invocations > 0 {
			successRate = float64(successes) / float64(invocations) * 100
		}

		snap.Modules[id] = ModuleSnapshot{
			Invocations: invocations,
			Successes:   successes,
			Failures:    m.Failures.Load(),
			AvgDuration: avgDur,
			Findings:    m.FindingCount.Load(),
			SuccessRate: successRate,
		}
	}

	return snap
}
