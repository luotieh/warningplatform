package scanrunner

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/orchestrate"
	"vulnscan-backend/template/engine"
)

const defaultModuleTimeout = 2 * time.Minute

// TargetHealth tracks connection success/failure for adaptive rate control.
type TargetHealth struct {
	mu         sync.Mutex
	successes  int
	failures   int
	totalRTTMs float64
}

func (h *TargetHealth) Record(success bool, rttMs float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if success {
		h.successes++
	} else {
		h.failures++
	}
	h.totalRTTMs += rttMs
}

func (h *TargetHealth) SuccessRate() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	total := h.successes + h.failures
	if total == 0 {
		return 1.0
	}
	return float64(h.successes) / float64(total)
}

func (h *TargetHealth) AvgRTTMs() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	total := h.successes + h.failures
	if total == 0 {
		return 0
	}
	return h.totalRTTMs / float64(total)
}

type Runner struct {
	db       *gorm.DB
	task     model.ScanTask
	cancelFn context.CancelFunc
	eventBus *EventBus

	progress      *ProgressTracker
	moduleTimeout time.Duration

	persistedKeys map[string]struct{}
	persistMu     sync.Mutex

	targetHealth map[string]*TargetHealth
	healthMu     sync.RWMutex

	logCh   chan model.ScanLog
	logDone chan struct{}

	adaptive    *orchestrate.AdaptiveController
	circuit     *orchestrate.CircuitBreaker
	dedup       *orchestrate.FindingDeduplicator
	prioritizer *orchestrate.ModulePrioritizer
	stream      *orchestrate.FindingStream
	enricher    *orchestrate.TargetEnricher
	checkpoint  *CheckpointManager
	strategy    *orchestrate.StrategyEngine

	eventBridge *EventBridge

	resultCache *ResultCache

	templateInstance *engine.TemplateInstance
	planResolver     *PlanResolver

	findingFilter *FindingFilter

	enginePolicy          EnginePolicy
	persistedFindingCount atomic.Int32
}

func NewRunner(db *gorm.DB, task model.ScanTask, eventBus *EventBus,
	tmplInstance *engine.TemplateInstance, planResolver *PlanResolver,
	opts ...RunnerOption) *Runner {
	r := &Runner{
		db:               db,
		task:             task,
		eventBus:         eventBus,
		moduleTimeout:    2 * time.Minute,
		progress:         NewProgressTracker(db, task.ID, len(task.Targets)),
		persistedKeys:    make(map[string]struct{}),
		targetHealth:     make(map[string]*TargetHealth),
		logCh:            make(chan model.ScanLog, 512),
		logDone:          make(chan struct{}),
		adaptive:         orchestrate.NewAdaptiveController(2, 50),
		circuit:          orchestrate.NewCircuitBreaker(5, 30*time.Second),
		dedup:            orchestrate.NewFindingDeduplicator(false),
		prioritizer:      orchestrate.NewModulePrioritizer(),
		stream:           orchestrate.NewFindingStream(1024),
		enricher:         orchestrate.NewTargetEnricher(),
		checkpoint:       NewCheckpointManager(db),
		strategy:         orchestrate.NewStrategyEngine(),
		resultCache:      NewResultCache(10000, 30*time.Minute),
		templateInstance: tmplInstance,
		planResolver:     planResolver,
	}
	for _, opt := range opts {
		opt(r)
	}
	go r.logWriter()
	return r
}

type RunnerOption func(*Runner)

func WithEventBridge(eb *EventBridge) RunnerOption {
	return func(r *Runner) {
		r.eventBridge = eb
	}
}

func (r *Runner) logWriter() {
	defer close(r.logDone)
	batch := make([]model.ScanLog, 0, 32)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := r.db.CreateInBatches(batch, 50).Error; err != nil {
			slog.Warn("[LogWriter] 日志批量写入失败", "error", err, "count", len(batch))
		}
		batch = batch[:0]
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case entry, ok := <-r.logCh:
			if !ok {
				flush()
				return
			}
			batch = append(batch, entry)
			if len(batch) >= 32 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (r *Runner) writeLog(level, message, stage, module string) {
	r.publishEvent(NewLogEvent(r.task.ID, level, message, stage, module))
	select {
	case r.logCh <- model.ScanLog{
		TaskID:  r.task.ID,
		Level:   level,
		Message: message,
		Stage:   stage,
		Module:  module,
	}:
	default:
		slog.Warn("[LogWriter] 日志 channel 已满，丢弃", "message", message)
	}
}

func (r *Runner) Cancel() {
	if r.cancelFn != nil {
		r.cancelFn()
	}
}

func (r *Runner) loadFilters() {
	var exclusions []model.ScanExclusion
	var fpRules []model.FPRule

	scopes := []string{model.ExclusionScopeGlobal}
	if r.task.TemplateID != "" {
		scopes = append(scopes, "template:"+r.task.TemplateID)
	}

	r.db.Where("enabled = ? AND scope IN ?", true, scopes).Find(&exclusions)
	r.db.Where("enabled = ?", true).Find(&fpRules)

	if len(exclusions) > 0 || len(fpRules) > 0 {
		r.findingFilter = NewFindingFilter(exclusions, fpRules)
		slog.Info("[Runner] 已加载过滤规则",
			"exclusions", len(exclusions),
			"fp_rules", len(fpRules),
		)
	}
}

func (r *Runner) GetProgress() *TaskProgress {
	return r.progress.Get()
}

func (r *Runner) GetTargetHealth(host string) *TargetHealth {
	r.healthMu.RLock()
	h, ok := r.targetHealth[host]
	r.healthMu.RUnlock()
	if ok {
		return h
	}

	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	if h, ok = r.targetHealth[host]; ok {
		return h
	}
	h = &TargetHealth{}
	r.targetHealth[host] = h
	return h
}

func (r *Runner) Execute(ctx context.Context) {
	defer func() {
		close(r.logCh)
		<-r.logDone
	}()
	defer r.tryMergeParentScanTask(context.Background())
	defer r.finalizeAfterRun(context.Background())

	r.loadFilters()

	r.enginePolicy = ParseEnginePolicy(mergeTaskConfigSource(r.task))
	r.persistedFindingCount.Store(0)
	if p := r.enginePolicy; p.CircuitFailThreshold > 0 && p.CircuitResetSeconds > 0 {
		r.circuit = orchestrate.NewCircuitBreaker(p.CircuitFailThreshold, time.Duration(p.CircuitResetSeconds)*time.Second)
	}
	if p := r.enginePolicy; p.AdaptiveMinConcurrency > 0 && p.AdaptiveMaxConcurrency >= p.AdaptiveMinConcurrency {
		r.adaptive = orchestrate.NewAdaptiveController(p.AdaptiveMinConcurrency, p.AdaptiveMaxConcurrency)
	}
	if p := r.enginePolicy; p.CacheMaxEntries > 0 && p.CacheTTLSeconds > 0 {
		r.resultCache = NewResultCache(p.CacheMaxEntries, time.Duration(p.CacheTTLSeconds)*time.Second)
	}

	slog.Info("[Runner] 开始执行任务", "task_id", r.task.ID, "targets", len(r.task.Targets))

	targets := buildTargets(r.task)
	config := buildConfig(r.task)

	stages, err := r.planResolver.Resolve(r.templateInstance)
	if err != nil {
		r.writeLog("error", "模板解析失败: "+err.Error(), "", "")
		r.progress.FinishTask(model.TaskStatusFailed, "模板解析失败: "+err.Error())
		return
	}

	r.moduleTimeout = DefaultTimeout(stages)
	if r.enginePolicy.ModuleTimeoutSeconds > 0 {
		r.moduleTimeout = time.Duration(r.enginePolicy.ModuleTimeoutSeconds) * time.Second
	}

	totalModules := TotalModules(stages)
	r.progress.SetStages(len(stages))
	r.progress.SetModulesTotal(totalModules)

	moduleIDs := StageModuleIDs(stages)
	r.writeLog("info",
		fmt.Sprintf("任务启动：%d 个目标, %d 个模块 (%v), %d 个阶段",
			len(targets), totalModules, moduleIDs, len(stages)),
		"", "")

	currentTargets := targets

	cb := StageCallbacks{
		OnModuleStart: func(stage, moduleID string) {
			if moduleID != "" {
				r.progress.BeginModule(moduleID)
			}
			r.progress.SyncToDB(stage)
			r.publishEvent(NewProgressEvent(r.task.ID, *r.progress.Get()))
		},
		OnModuleDone: func(stage, moduleID string) {
			if moduleID != "" {
				r.progress.EndModule(moduleID)
			}
			r.progress.IncrementModuleDone()
			r.progress.SyncToDB(stage)
			r.publishEvent(NewProgressEvent(r.task.ID, *r.progress.Get()))
		},
		OnModuleResult: func(findings []*core.Finding, stage, moduleID string) {
			r.progress.AppendFindings(findings)
			r.persistAndPublish(findings, stage, moduleID)
		},
		OnLog: func(level, message, stage, module string) {
			r.writeLog(level, message, stage, module)
		},
	}

	engineOpts := EngineOpts{
		Adaptive:    r.adaptive,
		Circuit:     r.circuit,
		Dedup:       r.dedup,
		Prioritizer: r.prioritizer,
		Stream:      r.stream,
		Checkpoint:  r.checkpoint,
		Strategy:    r.strategy,
		Cache:       r.resultCache,
		TaskID:      r.task.ID,

		TargetExclusionFilter: r.findingFilter,
	}

	r.executeDAG(ctx, stages, currentTargets, config, cb, engineOpts)

	if taskAlreadyCancelled(r.db, r.task.ID) {
		return
	}

	r.stream.Close()

	r.writeLog("info",
		fmt.Sprintf("扫描任务完成，共发现 %d 条结果 | 去重指纹数: %d | 自适应并发: %v | 熔断状态: %v",
			r.progress.Get().FindingCount,
			r.dedup.Count(),
			r.adaptive.Stats(),
			r.circuit.Stats()),
		"", "")
	if !taskAlreadyCancelled(r.db, r.task.ID) {
		r.progress.FinishTask(model.TaskStatusCompleted, "")
		r.publishEvent(NewDoneEvent(r.task.ID, model.TaskStatusCompleted, ""))
	}

	slog.Info("[Runner] 任务执行完成",
		"task_id", r.task.ID,
		"findings", r.progress.Get().FindingCount,
		"duration", time.Since(r.progress.startTime),
	)
}

func (r *Runner) persistAndPublish(findings []*core.Finding, stage, moduleID string) {
	if len(findings) == 0 {
		return
	}

	if r.findingFilter != nil {
		findings = r.findingFilter.FilterFindings(findings)
		if len(findings) == 0 {
			return
		}
	}

	var records []model.ScanFinding

	r.persistMu.Lock()
	for _, f := range findings {
		if r.enginePolicy.MaxFindingsPersisted > 0 && int(r.persistedFindingCount.Load()) >= r.enginePolicy.MaxFindingsPersisted {
			slog.Info("[Persist] 已达 engine.max_findings 上限，停止实时持久化",
				"task_id", r.task.ID, "limit", r.enginePolicy.MaxFindingsPersisted)
			break
		}
		if !r.enginePolicy.AllowPersistFinding(f) {
			continue
		}
		dedupKey := computeDedupKey(r.task.ID, f, r.enginePolicy.StrictDedup)
		if _, ok := r.persistedKeys[dedupKey]; ok {
			continue
		}
		r.persistedKeys[dedupKey] = struct{}{}
		records = append(records, findingToRecord(r.task, f))
		r.persistedFindingCount.Add(1)
	}
	r.persistMu.Unlock()

	if len(records) == 0 {
		return
	}

	created := r.batchPersistFindings(records)

	slog.Info("[Persist] 实时发现已写入",
		"task_id", r.task.ID, "module", moduleID,
		"records", len(records), "created", created,
	)

	r.writeLog("info",
		fmt.Sprintf("模块 [%s] 发现 %d 条新结果", moduleID, created),
		stage, moduleID)
	r.publishEvent(NewFindingEvent(r.task.ID, records, stage, moduleID))
	r.publishEvent(NewProgressEvent(r.task.ID, *r.progress.Get()))
}

const batchSize = 100

func (r *Runner) batchPersistFindings(records []model.ScanFinding) int {
	created := 0
	for i := 0; i < len(records); i += batchSize {
		end := i + batchSize
		if end > len(records) {
			end = len(records)
		}
		batch := records[i:end]

		result := r.db.CreateInBatches(batch, len(batch))
		if result.Error != nil {
			for _, rec := range batch {
				res := r.db.Where("task_id = ? AND target = ? AND module_id = ? AND title = ?",
					rec.TaskID, rec.Target, rec.ModuleID, rec.Title).
					FirstOrCreate(&rec)
				if res.Error == nil && res.RowsAffected == 1 {
					created++
				}
			}
		} else {
			created += int(result.RowsAffected)
		}
	}
	return created
}

func (r *Runner) publishEvent(evt ScanEvent) {
	if r.eventBus != nil {
		r.eventBus.Publish(r.task.ID, evt)
	}
}

// tryMergeParentScanTask 在子任务任意终态退出 Execute 时调用：若全部子任务已结束则合并父任务并触发父任务完成回调。
func (r *Runner) tryMergeParentScanTask(doneCtx context.Context) {
	pid := strings.TrimSpace(r.task.ParentID)
	if pid == "" {
		return
	}
	sp := NewTaskSplitter(r.db)
	merged, err := sp.MergeResults(pid)
	if err != nil {
		slog.Warn("[TaskSplitter] 合并父扫描任务失败", "parent_id", pid, "child_id", r.task.ID, "error", err)
		return
	}
	if !merged {
		return
	}
	if r.eventBridge != nil {
		r.eventBridge.OnScanComplete(doneCtx, pid)
	}
}

func buildTargets(task model.ScanTask) []*core.Target {
	var targets []*core.Target
	for _, addr := range task.Targets {
		targets = append(targets, parseTargetAddr(addr))
	}
	return targets
}

func parseTargetAddr(addr string) *core.Target {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return &core.Target{}
	}
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil {
			return &core.Target{Host: addr, URL: addr}
		}
		t := &core.Target{
			Host: u.Hostname(),
			URL:  addr,
		}
		if p := u.Port(); p != "" {
			fmt.Sscanf(p, "%d", &t.Port)
		} else if u.Scheme == "https" {
			t.Port = 443
		} else if u.Scheme == "http" {
			t.Port = 80
		}
		return t
	}
	if h, p, err := netSplitHostPort(addr); err == nil && p > 0 {
		return &core.Target{Host: h, Port: p}
	}
	return &core.Target{Host: addr}
}

func netSplitHostPort(hostport string) (host string, port int, err error) {
	if strings.HasPrefix(hostport, "[") {
		return "", 0, fmt.Errorf("unsupported")
	}
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return hostport, 0, fmt.Errorf("no port")
	}
	host = hostport[:i]
	var p int
	if _, scanErr := fmt.Sscanf(hostport[i+1:], "%d", &p); scanErr != nil {
		return "", 0, scanErr
	}
	return host, p, nil
}

func buildConfig(task model.ScanTask) map[string]interface{} {
	params := task.Parameters
	if params == nil {
		params = model.JSONMap{}
	}
	if _, ok := params["target_count"]; !ok {
		params = cloneJSONMap(params)
		params["target_count"] = countTargets(task.Targets)
	}
	config := ApplyDerivedAndPreset(params)
	config["scan_task_id"] = task.ID
	if strings.TrimSpace(task.ParentID) != "" {
		config["scan_parent_task_id"] = task.ParentID
	}
	return config
}

func isReconStage(name string) bool {
	return name == "recon" || name == "recon-fast" || name == "recon-deep" || name == "probe"
}

func extractDetectedProducts(findings []*core.Finding, config map[string]interface{}) []string {
	seen := make(map[string]struct{})

	if existing, ok := config["detected_products"].([]string); ok {
		for _, p := range existing {
			seen[strings.ToLower(p)] = struct{}{}
		}
	}

	for _, f := range findings {
		if f.Data == nil {
			continue
		}
		switch f.Type {
		case "fingerprint":
			if product := f.Data["product"]; product != "" {
				key := strings.ToLower(product)
				seen[key] = struct{}{}
			}
			if category := f.Data["category"]; category != "" {
				key := strings.ToLower(category)
				seen[key] = struct{}{}
			}
		case "tech_stack":
			if name := f.Data["name"]; name != "" {
				key := strings.ToLower(name)
				seen[key] = struct{}{}
			}
			if category := f.Data["category"]; category != "" {
				key := strings.ToLower(category)
				seen[key] = struct{}{}
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	products := make([]string, 0, len(seen))
	for p := range seen {
		products = append(products, p)
	}
	return products
}

func extractDetectedWAFs(findings []*core.Finding) []string {
	seen := make(map[string]struct{})
	for _, f := range findings {
		if f.Type != "waf" || f.Data == nil {
			continue
		}
		if waf := f.Data["waf"]; waf != "" {
			seen[strings.ToLower(waf)] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	wafs := make([]string, 0, len(seen))
	for w := range seen {
		wafs = append(wafs, w)
	}
	return wafs
}
