package scanrunner

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
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

	templateInstance *engine.TemplateInstance
	planResolver     *PlanResolver
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

	totalModules := TotalModules(stages)
	r.progress.SetStages(len(stages))
	r.progress.SetModulesTotal(totalModules)

	moduleIDs := StageModuleIDs(stages)
	r.writeLog("info",
		fmt.Sprintf("任务启动：%d 个目标, %d 个模块 (%v), %d 个阶段",
			len(targets), totalModules, moduleIDs, len(stages)),
		"", "")

	currentTargets := targets

	stageCtx := &StageContext{
		CompletedStages: make(map[string]StageResult),
		Params:          r.templateInstance.Params,
	}

	cb := StageCallbacks{
		OnModuleDone: func(stage string) {
			r.progress.IncrementModuleDone()
			r.progress.SyncToDB(stage)
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
		TaskID:      r.task.ID,
	}

	for i, stage := range stages {
		select {
		case <-ctx.Done():
			r.progress.FinishTask(model.TaskStatusCancelled, "任务被取消")
			return
		default:
		}

		if !ShouldRun(stage, stageCtx) {
			r.writeLog("info", fmt.Sprintf("阶段 [%s] 条件不满足，跳过", stage.name), stage.name, "")
			if cb.OnModuleDone != nil {
				for range stage.modules {
					cb.OnModuleDone(stage.name)
				}
			}
			continue
		}

		r.progress.SetCurrentStage(stage.name)
		r.progress.SyncToDB(stage.name)
		r.publishEvent(NewStageEvent(r.task.ID, stage.name, "started"))

		moduleNames := make([]string, 0, len(stage.modules))
		for _, m := range stage.modules {
			moduleNames = append(moduleNames, m.ID())
		}
		r.writeLog("info",
			fmt.Sprintf("阶段 [%s] 开始，包含 %d 个模块: %v", stage.name, len(stage.modules), moduleNames),
			stage.name, "")

		stageConfig := mergeConfig(config, stage.config)
		timeout := r.moduleTimeout
		if stage.timeout > 0 {
			timeout = stage.timeout
		}

		stageFindings, stageTargets := ExecuteStageWithOpts(
			ctx, r.task.ID, stage, currentTargets, stageConfig, timeout, cb, engineOpts,
		)

		stageCtx.CompletedStages[stage.name] = StageResult{
			Findings: stageFindings,
			Targets:  stageTargets,
		}

		if len(stageTargets) > 0 {
			currentTargets = r.enricher.EnrichTargets(currentTargets, stageTargets)
		}

		if isReconStage(stage.name) && len(stageFindings) > 0 {
			products := extractDetectedProducts(stageFindings, config)
			if len(products) > 0 {
				config["detected_products"] = products
				r.writeLog("info",
					fmt.Sprintf("检测到 %d 个产品/技术: %v", len(products), products),
					stage.name, "")
			}

			wafs := extractDetectedWAFs(stageFindings)
			if len(wafs) > 0 {
				config["detected_wafs"] = wafs
				r.writeLog("info",
					fmt.Sprintf("检测到 %d 个WAF: %v", len(wafs), wafs),
					stage.name, "")
			}
		}

		r.progress.SetScanned(len(targets))
		r.progress.IncrementStageDone()
		r.progress.SyncToDB(stage.name)
		r.publishEvent(NewStageEvent(r.task.ID, stage.name, "completed"))
		r.publishEvent(NewProgressEvent(r.task.ID, *r.progress.Get()))

		r.writeLog("info",
			fmt.Sprintf("阶段 [%s] 完成 (%d/%d)，本阶段发现 %d 条结果",
				stage.name, i+1, len(stages), len(stageFindings)),
			stage.name, "")

		select {
		case <-ctx.Done():
			r.writeLog("warn", "任务被取消", "", "")
			r.publishEvent(NewDoneEvent(r.task.ID, model.TaskStatusCancelled, "任务被取消"))
			r.progress.FinishTask(model.TaskStatusCancelled, "任务被取消")
			return
		default:
		}

		slog.Info("[Runner] Stage 完成", "task", r.task.ID, "stage", stage.name,
			"stage_num", i+1, "total_stages", len(stages),
			"findings_in_stage", len(stageFindings))
	}

	r.stream.Close()

	r.writeLog("info",
		fmt.Sprintf("扫描任务完成，共发现 %d 条结果 | 去重指纹数: %d | 自适应并发: %v | 熔断状态: %v",
			r.progress.Get().FindingCount,
			r.dedup.Count(),
			r.adaptive.Stats(),
			r.circuit.Stats()),
		"", "")
	r.progress.FinishTask(model.TaskStatusCompleted, "")
	r.publishEvent(NewDoneEvent(r.task.ID, model.TaskStatusCompleted, ""))

	if r.eventBridge != nil {
		r.eventBridge.OnScanComplete(ctx, r.task.ID)
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

	var records []model.ScanFinding

	r.persistMu.Lock()
	for _, f := range findings {
		dedupKey := computeDedupKey(r.task.ID, f)
		if _, ok := r.persistedKeys[dedupKey]; ok {
			continue
		}
		r.persistedKeys[dedupKey] = struct{}{}
		records = append(records, findingToRecord(r.task, f))
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

func buildTargets(task model.ScanTask) []*core.Target {
	var targets []*core.Target
	for _, addr := range task.Targets {
		targets = append(targets, &core.Target{Host: addr})
	}
	return targets
}

func buildConfig(task model.ScanTask) map[string]interface{} {
	config := make(map[string]interface{})
	if task.Parameters != nil {
		for k, v := range task.Parameters {
			config[k] = v
		}
	}
	return config
}

func isReconStage(name string) bool {
	return name == "recon" || name == "recon-fast" || name == "recon-deep"
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
