package scanrunner

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
	"vulnscan-backend/scan/scanhttp"
)

// QualityReport summarizes the quality and completeness of a scan task.
type QualityReport struct {
	TaskID    string    `json:"task_id"`
	CreatedAt time.Time `json:"created_at"`

	Targets     TargetQuality    `json:"targets"`
	Modules     ModuleQuality    `json:"modules"`
	Performance PerformanceStats `json:"performance"`
	Coverage    CoverageStats    `json:"coverage"`
	Warnings    []string         `json:"warnings,omitempty"`
	Score       int              `json:"score"`
}

type TargetQuality struct {
	Total       int `json:"total"`
	Reachable   int `json:"reachable"`
	Unreachable int `json:"unreachable"`
	WithHTTP    int `json:"with_http"`
	WithPorts   int `json:"with_ports"`
}

type ModuleQuality struct {
	Total     int            `json:"total"`
	Completed int            `json:"completed"`
	Failed    int            `json:"failed"`
	Skipped   int            `json:"skipped"`
	Timings   []ModuleTiming `json:"timings,omitempty"`
}

type ModuleTiming struct {
	ModuleID string        `json:"module_id"`
	Duration time.Duration `json:"duration_ms"`
	Status   string        `json:"status"`
	Findings int           `json:"findings"`
}

type PerformanceStats struct {
	TotalDuration     time.Duration `json:"total_duration_ms"`
	AvgModuleTime     time.Duration `json:"avg_module_time_ms"`
	HTTPCacheHitRate  float64       `json:"http_cache_hit_rate"`
	HTTPCacheHits     int64         `json:"http_cache_hits"`
	HTTPCacheMisses   int64         `json:"http_cache_misses"`
	DNSCacheHitRate   float64       `json:"dns_cache_hit_rate"`
	DNSCacheHits      int64         `json:"dns_cache_hits"`
	DNSCacheMisses    int64         `json:"dns_cache_misses"`
	ScopeFiltered     int           `json:"scope_filtered"`
	DedupFiltered     int           `json:"dedup_filtered"`
	ActiveHostBuckets int           `json:"active_host_buckets"`
}

type CoverageStats struct {
	TotalFindings     int            `json:"total_findings"`
	VulnFindings      int            `json:"vuln_findings"`
	ReconFindings     int            `json:"recon_findings"`
	SeverityBreakdown map[string]int `json:"severity_breakdown"`
	ModuleCoverage    map[string]int `json:"module_coverage"`
}

// QualityCollector tracks quality metrics during scan execution.
type QualityCollector struct {
	mu            sync.Mutex
	moduleTimings map[string]*moduleStat
	scopeFiltered int
	dedupFiltered int
	startTime     time.Time
}

type moduleStat struct {
	started  time.Time
	duration time.Duration
	status   string
	findings int
}

func NewQualityCollector() *QualityCollector {
	return &QualityCollector{
		moduleTimings: make(map[string]*moduleStat),
		startTime:     time.Now(),
	}
}

func (qc *QualityCollector) RecordModuleStart(moduleID string) {
	qc.mu.Lock()
	defer qc.mu.Unlock()
	qc.moduleTimings[moduleID] = &moduleStat{
		started: time.Now(),
		status:  "running",
	}
}

func (qc *QualityCollector) RecordModuleDone(moduleID string, findings int) {
	qc.mu.Lock()
	defer qc.mu.Unlock()
	if ms, ok := qc.moduleTimings[moduleID]; ok {
		ms.duration = time.Since(ms.started)
		ms.status = "completed"
		ms.findings = findings
	}
}

func (qc *QualityCollector) RecordModuleFailed(moduleID string) {
	qc.mu.Lock()
	defer qc.mu.Unlock()
	if ms, ok := qc.moduleTimings[moduleID]; ok {
		ms.duration = time.Since(ms.started)
		ms.status = "failed"
	}
}

func (qc *QualityCollector) AddScopeFiltered(count int) {
	qc.mu.Lock()
	qc.scopeFiltered += count
	qc.mu.Unlock()
}

func (qc *QualityCollector) AddDedupFiltered(count int) {
	qc.mu.Lock()
	qc.dedupFiltered += count
	qc.mu.Unlock()
}

// GenerateReport compiles the quality report after a scan completes.
func GenerateQualityReport(db *gorm.DB, taskID string, qc *QualityCollector) (*QualityReport, error) {
	var task model.ScanTask
	if err := db.First(&task, "id = ?", taskID).Error; err != nil {
		return nil, err
	}

	report := &QualityReport{
		TaskID:    taskID,
		CreatedAt: time.Now(),
	}

	report.Targets = buildTargetQuality(db, taskID, task.Targets)
	report.Modules = buildModuleQuality(qc)
	report.Performance = buildPerformanceStats(qc)
	report.Coverage = buildCoverageStats(db, taskID)
	report.Warnings = generateWarnings(report)
	report.Score = calculateScore(report)

	slog.Info("[QualityReport] 扫描质量报告已生成",
		"task_id", taskID,
		"score", report.Score,
		"targets_reachable", fmt.Sprintf("%d/%d", report.Targets.Reachable, report.Targets.Total),
		"modules_completed", fmt.Sprintf("%d/%d", report.Modules.Completed, report.Modules.Total),
		"findings", report.Coverage.TotalFindings,
	)

	return report, nil
}

func buildTargetQuality(db *gorm.DB, taskID string, targets []string) TargetQuality {
	tq := TargetQuality{
		Total: len(targets),
	}

	var portFindings int64
	db.Model(&model.ScanFinding{}).
		Where("task_id = ? AND type = ?", taskID, "port_open").
		Count(&portFindings)

	var httpFindings int64
	db.Model(&model.ScanFinding{}).
		Where("task_id = ? AND type IN ?", taskID, []string{"fingerprint", "tech_stack"}).
		Count(&httpFindings)

	var distinctTargets int64
	db.Model(&model.ScanFinding{}).
		Where("task_id = ?", taskID).
		Distinct("target").
		Count(&distinctTargets)

	tq.Reachable = int(distinctTargets)
	tq.Unreachable = tq.Total - tq.Reachable
	if tq.Unreachable < 0 {
		tq.Unreachable = 0
	}
	tq.WithPorts = int(portFindings)
	tq.WithHTTP = int(httpFindings)

	return tq
}

func buildModuleQuality(qc *QualityCollector) ModuleQuality {
	if qc == nil {
		return ModuleQuality{}
	}
	qc.mu.Lock()
	defer qc.mu.Unlock()

	mq := ModuleQuality{
		Total: len(qc.moduleTimings),
	}

	for id, ms := range qc.moduleTimings {
		switch ms.status {
		case "completed":
			mq.Completed++
		case "failed":
			mq.Failed++
		default:
			mq.Skipped++
		}
		mq.Timings = append(mq.Timings, ModuleTiming{
			ModuleID: id,
			Duration: ms.duration,
			Status:   ms.status,
			Findings: ms.findings,
		})
	}

	sort.Slice(mq.Timings, func(i, j int) bool {
		return mq.Timings[i].Duration > mq.Timings[j].Duration
	})

	return mq
}

func buildPerformanceStats(qc *QualityCollector) PerformanceStats {
	ps := PerformanceStats{}

	cache := scanhttp.GetGlobalResponseCache()
	ps.HTTPCacheHits, ps.HTTPCacheMisses = cache.Stats()
	ps.HTTPCacheHitRate = cache.HitRate()

	dnsCache := scanhttp.GetGlobalDNSCache()
	ps.DNSCacheHits, ps.DNSCacheMisses, _ = dnsCache.Stats()
	ps.DNSCacheHitRate = dnsCache.HitRate()

	hostRL := scanhttp.GetGlobalHostRateLimiter()
	ps.ActiveHostBuckets = hostRL.ActiveHosts()

	if qc != nil {
		ps.TotalDuration = time.Since(qc.startTime)
		ps.ScopeFiltered = qc.scopeFiltered
		ps.DedupFiltered = qc.dedupFiltered

		qc.mu.Lock()
		totalModuleTime := time.Duration(0)
		count := 0
		for _, ms := range qc.moduleTimings {
			if ms.status == "completed" {
				totalModuleTime += ms.duration
				count++
			}
		}
		qc.mu.Unlock()

		if count > 0 {
			ps.AvgModuleTime = totalModuleTime / time.Duration(count)
		}
	}

	return ps
}

func buildCoverageStats(db *gorm.DB, taskID string) CoverageStats {
	cs := CoverageStats{
		SeverityBreakdown: make(map[string]int),
		ModuleCoverage:    make(map[string]int),
	}

	var findings []struct {
		Category string
		Severity string
		ModuleID string
		Count    int64
	}
	db.Model(&model.ScanFinding{}).
		Select("category, severity, module_id, count(*) as count").
		Where("task_id = ?", taskID).
		Group("category, severity, module_id").
		Find(&findings)

	for _, f := range findings {
		cs.TotalFindings += int(f.Count)
		if f.Category == model.FindingCategoryVuln {
			cs.VulnFindings += int(f.Count)
		} else {
			cs.ReconFindings += int(f.Count)
		}
		sev := strings.ToLower(f.Severity)
		if sev == "" {
			sev = "info"
		}
		cs.SeverityBreakdown[sev] += int(f.Count)
		cs.ModuleCoverage[f.ModuleID] += int(f.Count)
	}

	return cs
}

func generateWarnings(report *QualityReport) []string {
	var warnings []string

	if report.Targets.Total > 0 {
		reachRate := float64(report.Targets.Reachable) / float64(report.Targets.Total)
		if reachRate < 0.5 {
			warnings = append(warnings, fmt.Sprintf("目标可达率较低 (%.0f%%)，请检查目标列表是否正确或网络连通性", reachRate*100))
		}
	}

	if report.Modules.Failed > 0 {
		warnings = append(warnings, fmt.Sprintf("%d 个模块执行失败，部分检测结果可能缺失", report.Modules.Failed))
	}

	if report.Targets.WithHTTP == 0 && report.Coverage.VulnFindings == 0 {
		warnings = append(warnings, "未检测到 HTTP 服务，Web 漏洞模块已跳过")
	}

	if report.Performance.HTTPCacheHitRate > 0.8 {
		warnings = append(warnings, fmt.Sprintf("HTTP 缓存命中率 %.0f%%，大量请求复用了缓存结果", report.Performance.HTTPCacheHitRate*100))
	}

	if report.Performance.ScopeFiltered > 0 {
		warnings = append(warnings, fmt.Sprintf("域名范围过滤拦截了 %d 条外域结果", report.Performance.ScopeFiltered))
	}

	for _, mt := range report.Modules.Timings {
		if mt.Duration > 5*time.Minute {
			warnings = append(warnings, fmt.Sprintf("模块 %s 耗时过长 (%.1f 分钟)", mt.ModuleID, mt.Duration.Minutes()))
		}
	}

	return warnings
}

func calculateScore(report *QualityReport) int {
	score := 100

	// Target reachability (max -30)
	if report.Targets.Total > 0 {
		reachRate := float64(report.Targets.Reachable) / float64(report.Targets.Total)
		if reachRate < 0.8 {
			penalty := int((0.8 - reachRate) * 37.5) // max 30
			score -= penalty
		}
	}

	// Module completion (max -30)
	if report.Modules.Total > 0 {
		completionRate := float64(report.Modules.Completed) / float64(report.Modules.Total)
		if completionRate < 0.9 {
			penalty := int((0.9 - completionRate) * 33) // max ~30
			score -= penalty
		}
	}

	// Failed modules (max -20)
	score -= report.Modules.Failed * 5

	// No findings penalty (max -10)
	if report.Coverage.TotalFindings == 0 {
		score -= 10
	}

	// Bonus for vuln findings
	if report.Coverage.VulnFindings > 0 {
		score += 5
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}
