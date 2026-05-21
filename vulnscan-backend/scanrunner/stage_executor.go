package scanrunner

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/orchestrate"
)

type moduleResult struct {
	moduleID string
	findings []*core.Finding
	targets  []*core.Target
	err      error
	duration time.Duration
}

type StageCallbacks struct {
	OnModuleStart  func(stage, moduleID string)
	OnModuleDone   func(stage, moduleID string)
	OnModuleResult func(findings []*core.Finding, stage, moduleID string)
	OnLog          func(level, message, stage, module string)
}

const moduleHeartbeatInterval = 8 * time.Second

func startModuleHeartbeat(ctx context.Context, stageName, moduleID string, start time.Time, cb StageCallbacks) func() {
	if cb.OnLog == nil {
		return func() {}
	}
	hbCtx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(moduleHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				elapsed := time.Since(start).Round(time.Second)
				cb.OnLog("info", fmt.Sprintf("模块 [%s] 执行中，已耗时 %s", moduleID, elapsed), stageName, moduleID)
			}
		}
	}()
	return cancel
}

type EngineOpts struct {
	Adaptive    *orchestrate.AdaptiveController
	Circuit     *orchestrate.CircuitBreaker
	Dedup       *orchestrate.FindingDeduplicator
	Prioritizer *orchestrate.ModulePrioritizer
	Stream      *orchestrate.FindingStream
	Checkpoint  *CheckpointManager
	Strategy    *orchestrate.StrategyEngine
	Cache       *ResultCache
	TaskID      string

	// TargetExclusionFilter 若设置，在模块执行前按排除规则过滤目标（提高效率）。
	TargetExclusionFilter *FindingFilter
}

const cancelGracePeriod = 10 * time.Second

func ExecuteStage(
	ctx context.Context,
	taskID string,
	stage stageGroup,
	targets []*core.Target,
	config map[string]interface{},
	moduleTimeout time.Duration,
	cb StageCallbacks,
) ([]*core.Finding, []*core.Target) {
	return ExecuteStageWithOpts(ctx, taskID, stage, targets, config, moduleTimeout, cb, EngineOpts{})
}

func ExecuteStageWithOpts(
	ctx context.Context,
	taskID string,
	stage stageGroup,
	targets []*core.Target,
	config map[string]interface{},
	moduleTimeout time.Duration,
	cb StageCallbacks,
	opts EngineOpts,
) ([]*core.Finding, []*core.Target) {
	if len(stage.modules) == 0 {
		return nil, nil
	}

	mods := stage.modules
	if opts.Strategy != nil {
		stack := opts.Strategy.DetectTechStack(nil, targets)
		mods = opts.Strategy.FilterModules(mods, stack)
	}
	if opts.Prioritizer != nil {
		mods = opts.Prioritizer.SortModules(mods)
	}

	if len(mods) == 0 {
		return nil, nil
	}

	modsBeforeWeb := len(mods)
	mods = filterWebVulnModules(mods, config)
	if skipped := modsBeforeWeb - len(mods); skipped > 0 && cb.OnModuleDone != nil {
		for i := 0; i < skipped; i++ {
			cb.OnModuleDone(stage.name, "")
		}
	}
	if len(mods) == 0 {
		return nil, nil
	}

	if len(mods) == 1 {
		return executeSingleWithOpts(ctx, taskID, stage.name, mods[0], targets, config, moduleTimeout, cb, opts)
	}
	return executeConcurrentWithOpts(ctx, taskID, stage, mods, targets, config, moduleTimeout, cb, opts)
}

func executeSingleWithOpts(
	ctx context.Context,
	taskID, stageName string,
	mod core.ScanModule,
	targets []*core.Target,
	config map[string]interface{},
	moduleTimeout time.Duration,
	cb StageCallbacks,
	opts EngineOpts,
) (findings []*core.Finding, newTargets []*core.Target) {
	defer func() {
		if rv := recover(); rv != nil {
			slog.Error("[Executor] 模块 panic", "task", taskID, "module", mod.ID(), "panic", rv)
			if cb.OnLog != nil {
				cb.OnLog("error", fmt.Sprintf("模块 [%s] panic: %v", mod.ID(), rv), stageName, mod.ID())
			}
			if cb.OnModuleDone != nil {
				cb.OnModuleDone(stageName, mod.ID())
			}
			findings = nil
			newTargets = nil
		}
	}()

	if opts.Checkpoint != nil && opts.Checkpoint.IsModuleCompleted(taskID, stageName, mod.ID()) {
		slog.Info("[Executor] 模块已完成(checkpoint)，跳过", "task", taskID, "module", mod.ID())
		if cb.OnModuleDone != nil {
			cb.OnModuleDone(stageName, mod.ID())
		}
		return nil, nil
	}

	if opts.TargetExclusionFilter != nil && len(targets) > 0 {
		targets = filterTargetsForExclusions(opts.TargetExclusionFilter, targets)
		if len(targets) == 0 {
			slog.Info("[Executor] 目标均被排除规则过滤，跳过模块", "task", taskID, "module", mod.ID())
			if cb.OnModuleDone != nil {
				cb.OnModuleDone(stageName, mod.ID())
			}
			return nil, nil
		}
	}

	if opts.Cache != nil && len(targets) == 1 {
		cacheKey := opts.Cache.Key(targets[0].Host, mod.ID(), config)
		if cached, hit := opts.Cache.Get(cacheKey); hit {
			slog.Info("[Executor] 缓存命中", "task", taskID, "module", mod.ID())
			if cb.OnModuleDone != nil {
				cb.OnModuleDone(stageName, mod.ID())
			}
			if cb.OnModuleResult != nil && len(cached) > 0 {
				cb.OnModuleResult(cached, stageName, mod.ID())
			}
			if cb.OnLog != nil {
				cb.OnLog("info", fmt.Sprintf("模块 [%s] 缓存命中，%d 条结果", mod.ID(), len(cached)), stageName, mod.ID())
			}
			return cached, nil
		}
	}

	if opts.Circuit != nil && !opts.Circuit.CanExecute(mod.ID()) {
		if cb.OnLog != nil {
			cb.OnLog("warn", fmt.Sprintf("模块 [%s] 已熔断，跳过执行", mod.ID()), stageName, mod.ID())
		}
		if cb.OnModuleDone != nil {
			cb.OnModuleDone(stageName, mod.ID())
		}
		return nil, nil
	}

	if opts.Checkpoint != nil {
		targetStrs := make([]string, 0, len(targets))
		for _, t := range targets {
			if t.Host != "" {
				targetStrs = append(targetStrs, t.Host)
			} else if t.IP != "" {
				targetStrs = append(targetStrs, t.IP)
			}
		}
		opts.Checkpoint.SaveModuleStart(taskID, stageName, mod.ID(), targetStrs)
	}

	modCtx, modCancel := context.WithTimeout(ctx, moduleTimeout)
	defer modCancel()

	if cb.OnModuleStart != nil {
		cb.OnModuleStart(stageName, mod.ID())
	}
	if cb.OnLog != nil {
		cb.OnLog("info", fmt.Sprintf("模块 [%s] 开始执行", mod.ID()), stageName, mod.ID())
	}
	slog.Info("[Executor] 模块开始", "task", taskID, "module", mod.ID(), "stage", stageName)
	start := time.Now()
	stopHeartbeat := startModuleHeartbeat(modCtx, stageName, mod.ID(), start, cb)
	defer stopHeartbeat()

	var result *core.ModuleResult
	var err error

	if opts.Circuit != nil {
		result, err = orchestrate.RunWithRetry(modCtx, mod, targets, ModuleConfigFor(mod.ID(), config), orchestrate.DefaultRetryConfig)
	} else {
		result, err = mod.Run(modCtx, targets, ModuleConfigFor(mod.ID(), config))
	}

	dur := time.Since(start)
	latencyMs := float64(dur.Milliseconds())

	if cb.OnModuleDone != nil {
		cb.OnModuleDone(stageName, mod.ID())
	}

	if err != nil {
		if opts.Adaptive != nil {
			opts.Adaptive.RecordFailure(latencyMs)
		}
		if opts.Circuit != nil {
			opts.Circuit.RecordFailure(mod.ID())
		}
		if opts.Prioritizer != nil {
			opts.Prioritizer.RecordResult(mod.ID(), 0, 0, latencyMs, false)
		}
		slog.Warn("[Executor] 模块执行失败", "task", taskID, "module", mod.ID(), "error", err)
		if cb.OnLog != nil {
			cb.OnLog("error", fmt.Sprintf("模块 [%s] 执行失败: %v (耗时 %s)", mod.ID(), err, dur.Round(time.Millisecond)), stageName, mod.ID())
		}
		if opts.Checkpoint != nil {
			opts.Checkpoint.SaveModuleFailed(taskID, stageName, mod.ID(), err.Error())
		}
		return nil, nil
	}

	if result == nil {
		return nil, nil
	}

	if opts.Adaptive != nil {
		opts.Adaptive.RecordSuccess(latencyMs)
	}
	if opts.Circuit != nil {
		opts.Circuit.RecordSuccess(mod.ID())
	}

	modFindings := result.Findings
	if opts.Dedup != nil {
		modFindings = opts.Dedup.DeduplicateFindings(taskID, modFindings)
	}

	if opts.Prioritizer != nil {
		opts.Prioritizer.RecordResult(mod.ID(), len(modFindings), len(result.Targets), latencyMs, true)
	}

	if opts.Checkpoint != nil {
		opts.Checkpoint.SaveModuleComplete(taskID, stageName, mod.ID(), len(modFindings), len(result.Targets))
	}

	if opts.Stream != nil {
		opts.Stream.Send(&orchestrate.FindingBatch{
			Stage:    stageName,
			ModuleID: mod.ID(),
			Findings: modFindings,
			Targets:  result.Targets,
		})
	}

	slog.Info("[Executor] 模块完成", "task", taskID, "module", mod.ID(),
		"findings", len(modFindings), "duration", dur.Round(time.Millisecond))
	if cb.OnLog != nil {
		cb.OnLog("info", fmt.Sprintf("模块 [%s] 完成，发现 %d 条结果 (耗时 %s)", mod.ID(), len(modFindings), dur.Round(time.Millisecond)), stageName, mod.ID())
	}
	if cb.OnModuleResult != nil {
		cb.OnModuleResult(modFindings, stageName, mod.ID())
	}

	if opts.Cache != nil && len(targets) == 1 {
		cacheKey := opts.Cache.Key(targets[0].Host, mod.ID(), config)
		opts.Cache.Set(cacheKey, modFindings)
	}

	return modFindings, result.Targets
}

func executeConcurrentWithOpts(
	ctx context.Context,
	taskID string,
	stage stageGroup,
	mods []core.ScanModule,
	targets []*core.Target,
	config map[string]interface{},
	moduleTimeout time.Duration,
	cb StageCallbacks,
	opts EngineOpts,
) ([]*core.Finding, []*core.Target) {
	results := make(chan moduleResult, len(mods))
	var wg sync.WaitGroup

	concurrency := len(mods)
	if opts.Adaptive != nil {
		adaptive := opts.Adaptive.CurrentConcurrency()
		if adaptive < concurrency {
			concurrency = adaptive
		}
	}

	sem := make(chan struct{}, concurrency)

	stageTimeout := time.AfterFunc(moduleTimeout+30*time.Second, func() {
		slog.Warn("[Executor] Stage 整体超时", "task", taskID, "stage", stage.name)
	})
	defer stageTimeout.Stop()

	if opts.TargetExclusionFilter != nil && len(targets) > 0 {
		targets = filterTargetsForExclusions(opts.TargetExclusionFilter, targets)
		if len(targets) == 0 {
			slog.Info("[Executor] 并发阶段目标均被排除规则过滤，跳过", "task", taskID, "stage", stage.name)
			return nil, nil
		}
	}

	for _, mod := range mods {
		if opts.Checkpoint != nil && opts.Checkpoint.IsModuleCompleted(taskID, stage.name, mod.ID()) {
			slog.Info("[Executor] 模块已完成(checkpoint)，跳过", "task", taskID, "module", mod.ID())
			results <- moduleResult{moduleID: mod.ID()}
			continue
		}

		if opts.Circuit != nil && !opts.Circuit.CanExecute(mod.ID()) {
			if cb.OnLog != nil {
				cb.OnLog("warn", fmt.Sprintf("模块 [%s] 已熔断，跳过执行", mod.ID()), stage.name, mod.ID())
			}
			results <- moduleResult{moduleID: mod.ID(), err: fmt.Errorf("circuit open")}
			continue
		}

		wg.Add(1)
		go func(m core.ScanModule) {
			defer wg.Done()
			defer func() {
				if rv := recover(); rv != nil {
					slog.Error("[Executor] 模块 panic", "module", m.ID(), "panic", rv)
					results <- moduleResult{moduleID: m.ID(), err: fmt.Errorf("panic: %v", rv)}
				}
			}()

			if opts.Adaptive != nil && opts.Adaptive.IsOpen() {
				results <- moduleResult{moduleID: m.ID(), err: fmt.Errorf("adaptive circuit open")}
				return
			}

			sem <- struct{}{}
			defer func() { <-sem }()

			if opts.Checkpoint != nil {
				opts.Checkpoint.SaveModuleStart(taskID, stage.name, m.ID(), nil)
			}

			modCtx, modCancel := context.WithTimeout(ctx, moduleTimeout)
			defer modCancel()

			if cb.OnModuleStart != nil {
				cb.OnModuleStart(stage.name, m.ID())
			}
			if cb.OnLog != nil {
				cb.OnLog("info", fmt.Sprintf("模块 [%s] 开始执行", m.ID()), stage.name, m.ID())
			}
			slog.Info("[Executor] 模块开始", "task", taskID, "module", m.ID(), "stage", stage.name)
			start := time.Now()
			stopHeartbeat := startModuleHeartbeat(modCtx, stage.name, m.ID(), start, cb)
			defer stopHeartbeat()

			var res *core.ModuleResult
			var err error
			modCfg := ModuleConfigFor(m.ID(), config)
			if opts.Circuit != nil {
				res, err = orchestrate.RunWithRetry(modCtx, m, targets, modCfg, orchestrate.DefaultRetryConfig)
			} else {
				res, err = m.Run(modCtx, targets, modCfg)
			}

			dur := time.Since(start)
			latencyMs := float64(dur.Milliseconds())

			if dur > moduleTimeout/2 {
				slog.Warn("[Executor] 模块耗时较长", "task", taskID, "module", m.ID(), "duration", dur.Round(time.Second))
			}

			mr := moduleResult{
				moduleID: m.ID(),
				err:      err,
				duration: dur,
			}

			if err != nil {
				if opts.Adaptive != nil {
					opts.Adaptive.RecordFailure(latencyMs)
				}
				if opts.Circuit != nil {
					opts.Circuit.RecordFailure(m.ID())
				}
				if opts.Prioritizer != nil {
					opts.Prioritizer.RecordResult(m.ID(), 0, 0, latencyMs, false)
				}
				if opts.Checkpoint != nil {
					opts.Checkpoint.SaveModuleFailed(taskID, stage.name, m.ID(), err.Error())
				}
			} else if res != nil {
				findings := res.Findings
				if opts.Dedup != nil {
					findings = opts.Dedup.DeduplicateFindings(taskID, findings)
				}
				mr.findings = findings
				mr.targets = res.Targets

				if opts.Adaptive != nil {
					opts.Adaptive.RecordSuccess(latencyMs)
				}
				if opts.Circuit != nil {
					opts.Circuit.RecordSuccess(m.ID())
				}
				if opts.Prioritizer != nil {
					opts.Prioritizer.RecordResult(m.ID(), len(findings), len(res.Targets), latencyMs, true)
				}
				if opts.Checkpoint != nil {
					opts.Checkpoint.SaveModuleComplete(taskID, stage.name, m.ID(), len(findings), len(res.Targets))
				}
				if opts.Stream != nil {
					opts.Stream.Send(&orchestrate.FindingBatch{
						Stage:    stage.name,
						ModuleID: m.ID(),
						Findings: findings,
						Targets:  res.Targets,
					})
				}
			}
			results <- mr
		}(mod)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return collectResults(ctx, taskID, stage, results, len(mods), cb)
}

func collectResults(
	ctx context.Context,
	taskID string,
	stage stageGroup,
	results <-chan moduleResult,
	total int,
	cb StageCallbacks,
) ([]*core.Finding, []*core.Target) {
	var allFindings []*core.Finding
	var allTargets []*core.Target
	received := 0

	for received < total {
		select {
		case mr, ok := <-results:
			if !ok {
				goto done
			}
			received++
			if cb.OnModuleDone != nil {
				cb.OnModuleDone(stage.name, mr.moduleID)
			}

			if mr.err != nil {
				slog.Warn("[Executor] 模块执行失败", "task", taskID, "module", mr.moduleID, "error", mr.err)
				if cb.OnLog != nil {
					cb.OnLog("error", fmt.Sprintf("模块 [%s] 执行失败: %v (耗时 %s)", mr.moduleID, mr.err, mr.duration.Round(time.Millisecond)), stage.name, mr.moduleID)
				}
				continue
			}

			allFindings = append(allFindings, mr.findings...)
			allTargets = append(allTargets, mr.targets...)

			if cb.OnModuleResult != nil {
				cb.OnModuleResult(mr.findings, stage.name, mr.moduleID)
			}

			if cb.OnLog != nil {
				cb.OnLog("info", fmt.Sprintf("模块 [%s] 完成，发现 %d 条结果 (耗时 %s)", mr.moduleID, len(mr.findings), mr.duration.Round(time.Millisecond)), stage.name, mr.moduleID)
			}

			slog.Info("[Executor] 模块完成", "task", taskID, "module", mr.moduleID,
				"findings", len(mr.findings), "duration", mr.duration.Round(time.Millisecond))

		case <-ctx.Done():
			slog.Warn("[Executor] 取消信号", "task", taskID, "stage", stage.name,
				"received", received, "total", total)
			drainRemaining(taskID, stage, results, total, received, cb)
			goto done
		}
	}

done:
	return allFindings, allTargets
}

func drainRemaining(
	taskID string,
	stage stageGroup,
	results <-chan moduleResult,
	total, received int,
	cb StageCallbacks,
) {
	graceTimer := time.NewTimer(cancelGracePeriod)
	defer graceTimer.Stop()

	for received < total {
		select {
		case mr, ok := <-results:
			if !ok {
				return
			}
			received++
			if cb.OnModuleDone != nil {
				cb.OnModuleDone(stage.name, mr.moduleID)
			}
			if mr.err == nil && cb.OnModuleResult != nil {
				cb.OnModuleResult(mr.findings, stage.name, mr.moduleID)
			}
		case <-graceTimer.C:
			remaining := total - received
			for i := 0; i < remaining; i++ {
				if cb.OnModuleDone != nil {
					cb.OnModuleDone(stage.name, "")
				}
			}
			slog.Warn("[Executor] 放弃等待未完成模块", "task", taskID, "stage", stage.name, "abandoned", remaining)
			return
		}
	}
}
