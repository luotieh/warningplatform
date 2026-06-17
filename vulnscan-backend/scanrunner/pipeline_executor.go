package scanrunner

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"code.yt-security.com/public/scanengine/core"
)

// PipelineExecutor implements streaming pipeline execution where
// discovered targets flow immediately into the next stage without
// waiting for the current stage to complete all targets.
type PipelineExecutor struct {
	taskID        string
	moduleTimeout time.Duration
	enricher      *enricherAdapter
	cb            StageCallbacks
	opts          EngineOpts
	config        map[string]interface{}
}

type enricherAdapter struct {
	inner interface {
		EnrichTargets(existing, newTargets []*core.Target) []*core.Target
	}
}

func (r *Runner) executePipeline(
	ctx context.Context,
	stages []stageGroup,
	targets []*core.Target,
	config map[string]interface{},
	cb StageCallbacks,
	engineOpts EngineOpts,
) {
	if len(stages) < 2 {
		r.executeSequential(ctx, stages, targets, config, cb, engineOpts)
		return
	}

	discoverIdx := -1
	probeIdx := -1
	for i, s := range stages {
		if isHostDiscoveryStage(s.name) {
			discoverIdx = i
		}
		if isPortScanStage(s.name) {
			probeIdx = i
		}
	}

	if probeIdx < 0 {
		r.executeSequential(ctx, stages, targets, config, cb, engineOpts)
		return
	}

	slog.Info("[Pipeline] 启用流水线模式", "task_id", r.task.ID,
		"stages", len(stages), "discover_idx", discoverIdx, "probe_idx", probeIdx)

	targetCh := make(chan *core.Target, 1024)
	var mu sync.Mutex
	var allFindings []*core.Finding

	if discoverIdx >= 0 && discoverIdx < probeIdx {
		r.progress.SetCurrentStage(stages[discoverIdx].name)
		r.publishEvent(NewStageEvent(r.task.ID, stages[discoverIdx].name, "started"))

		go func() {
			defer close(targetCh)

			discoverStage := stages[discoverIdx]
			for _, mod := range discoverStage.modules {
				if streamMod, ok := mod.(core.StreamingModule); ok {
					streamMod.RunStreaming(ctx, targets, ModuleConfigFor(mod.ID(), config), func(findings []*core.Finding, newTargets []*core.Target) {
						if cb.OnModuleResult != nil && len(findings) > 0 {
							cb.OnModuleResult(findings, discoverStage.name, mod.ID())
						}
						mu.Lock()
						allFindings = append(allFindings, findings...)
						mu.Unlock()
						for _, t := range newTargets {
							select {
							case targetCh <- t:
							case <-ctx.Done():
								return
							}
						}
					})
				} else {
					result, _ := mod.Run(ctx, targets, ModuleConfigFor(mod.ID(), config))
					if result != nil {
						if cb.OnModuleResult != nil && len(result.Findings) > 0 {
							cb.OnModuleResult(result.Findings, discoverStage.name, mod.ID())
						}
						mu.Lock()
						allFindings = append(allFindings, result.Findings...)
						mu.Unlock()
						for _, t := range result.Targets {
							select {
							case targetCh <- t:
							case <-ctx.Done():
								return
							}
						}
					}
				}
				if cb.OnModuleDone != nil {
					cb.OnModuleDone(discoverStage.name, mod.ID())
				}
			}
		}()
	} else {
		go func() {
			defer close(targetCh)
			for _, t := range targets {
				select {
				case targetCh <- t:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	portResultCh := make(chan *core.Target, 1024)
	portStage := stages[probeIdx]

	r.progress.SetCurrentStage(portStage.name)
	r.publishEvent(NewStageEvent(r.task.ID, portStage.name, "started"))

	var portWg sync.WaitGroup
	portWg.Add(1)
	go func() {
		defer portWg.Done()
		defer close(portResultCh)

		var batchTargets []*core.Target
		batchTimer := time.NewTimer(500 * time.Millisecond)
		defer batchTimer.Stop()

		processPortBatch := func(batch []*core.Target) {
			if len(batch) == 0 {
				return
			}
			for _, mod := range portStage.modules {
				if cb.OnModuleStart != nil {
					cb.OnModuleStart(portStage.name, mod.ID())
				}
				if streamMod, ok := mod.(core.StreamingModule); ok {
					streamMod.RunStreaming(ctx, batch, ModuleConfigFor(mod.ID(), config), func(findings []*core.Finding, newTargets []*core.Target) {
						if cb.OnModuleResult != nil && len(findings) > 0 {
							cb.OnModuleResult(findings, portStage.name, mod.ID())
						}
						mu.Lock()
						allFindings = append(allFindings, findings...)
						mu.Unlock()
						for _, t := range newTargets {
							select {
							case portResultCh <- t:
							case <-ctx.Done():
								return
							}
						}
					})
				} else {
					result, _ := mod.Run(ctx, batch, ModuleConfigFor(mod.ID(), config))
					if result != nil {
						if cb.OnModuleResult != nil && len(result.Findings) > 0 {
							cb.OnModuleResult(result.Findings, portStage.name, mod.ID())
						}
						mu.Lock()
						allFindings = append(allFindings, result.Findings...)
						mu.Unlock()
						for _, t := range result.Targets {
							select {
							case portResultCh <- t:
							case <-ctx.Done():
								return
							}
						}
					}
				}
				if cb.OnModuleDone != nil {
					cb.OnModuleDone(portStage.name, mod.ID())
				}
			}
		}

		for {
			select {
			case <-ctx.Done():
				processPortBatch(batchTargets)
				return
			case t, ok := <-targetCh:
				if !ok {
					processPortBatch(batchTargets)
					return
				}
				if r.scopeFilter != nil {
					host := t.Host
					if host == "" {
						host = t.IP
					}
					if !r.scopeFilter.InScope(host) {
						continue
					}
				}
				batchTargets = append(batchTargets, t)
				if len(batchTargets) >= 32 {
					processPortBatch(batchTargets)
					batchTargets = nil
					batchTimer.Reset(500 * time.Millisecond)
				}
			case <-batchTimer.C:
				if len(batchTargets) > 0 {
					processPortBatch(batchTargets)
					batchTargets = nil
				}
				batchTimer.Reset(500 * time.Millisecond)
			}
		}
	}()

	remainingStages := stages[probeIdx+1:]
	if len(remainingStages) > 0 {
		var serviceWg sync.WaitGroup
		serviceWg.Add(1)
		go func() {
			defer serviceWg.Done()

			var batchTargets []*core.Target
			batchTimer := time.NewTimer(300 * time.Millisecond)
			defer batchTimer.Stop()

			processServiceBatch := func(batch []*core.Target) {
				if len(batch) == 0 {
					return
				}
				for _, stage := range remainingStages {
					r.progress.SetCurrentStage(stage.name)
					r.publishEvent(NewStageEvent(r.task.ID, stage.name, "started"))

					stageConfig := mergeConfig(config, stage.config)
					for _, mod := range stage.modules {
						if cb.OnModuleStart != nil {
							cb.OnModuleStart(stage.name, mod.ID())
						}
						if streamMod, ok := mod.(core.StreamingModule); ok {
							streamMod.RunStreaming(ctx, batch, ModuleConfigFor(mod.ID(), stageConfig), func(findings []*core.Finding, newTargets []*core.Target) {
								if cb.OnModuleResult != nil && len(findings) > 0 {
									cb.OnModuleResult(findings, stage.name, mod.ID())
								}
								mu.Lock()
								allFindings = append(allFindings, findings...)
								mu.Unlock()
							})
						} else {
							result, _ := mod.Run(ctx, batch, ModuleConfigFor(mod.ID(), stageConfig))
							if result != nil && cb.OnModuleResult != nil && len(result.Findings) > 0 {
								cb.OnModuleResult(result.Findings, stage.name, mod.ID())
								mu.Lock()
								allFindings = append(allFindings, result.Findings...)
								mu.Unlock()
							}
						}
						if cb.OnModuleDone != nil {
							cb.OnModuleDone(stage.name, mod.ID())
						}
					}
				}
			}

			for {
				select {
				case <-ctx.Done():
					processServiceBatch(batchTargets)
					return
				case t, ok := <-portResultCh:
					if !ok {
						processServiceBatch(batchTargets)
						return
					}
					if r.scopeFilter != nil {
						host := t.Host
						if host == "" {
							host = t.IP
						}
						if !r.scopeFilter.InScope(host) {
							continue
						}
					}
					batchTargets = append(batchTargets, t)
					if len(batchTargets) >= 16 {
						processServiceBatch(batchTargets)
						batchTargets = nil
						batchTimer.Reset(300 * time.Millisecond)
					}
				case <-batchTimer.C:
					if len(batchTargets) > 0 {
						processServiceBatch(batchTargets)
						batchTargets = nil
					}
					batchTimer.Reset(300 * time.Millisecond)
				}
			}
		}()
		serviceWg.Wait()
	}

	portWg.Wait()
}

func isPortScanStage(name string) bool {
	return name == "port" || name == "port_scan" || name == "portscan" || name == "scan"
}
