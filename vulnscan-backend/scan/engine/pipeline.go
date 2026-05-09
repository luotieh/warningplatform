package engine

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

type PipelineStage struct {
	Name     string
	Modules  []ScanModule
	Parallel bool
}

type Pipeline struct {
	stages          []PipelineStage
	pool            *WorkerPool
	limiter         *RateLimiter
	findings        []*Finding
	techDetector    *AdvancedTechDetector
	moduleCutter    *SmartModuleCutter
	dedup           *MultiLayerDeduplicator
	propagator      *SmartTargetPropagator
	resourceMonitor *ResourceAwareAdaptiveController
}

func NewPipeline(poolSize, globalRate, targetRate int) *Pipeline {
	return &Pipeline{
		pool:            NewWorkerPool(poolSize),
		limiter:         NewRateLimiter(globalRate, targetRate),
		techDetector:    NewAdvancedTechDetector(),
		moduleCutter:    NewSmartModuleCutter(1.0),
		dedup:           NewMultiLayerDeduplicator(1000000, 0.01, false, nil),
		propagator:      NewSmartTargetPropagator(),
		resourceMonitor: NewResourceAwareAdaptiveController(10, 50, 5*time.Second),
	}
}

func (p *Pipeline) AddStage(stage PipelineStage) {
	p.stages = append(p.stages, stage)
}

func (p *Pipeline) Run(ctx context.Context, targets []*Target) ([]*Finding, error) {
	currentTargets := targets

	for _, stage := range p.stages {
		select {
		case <-ctx.Done():
			return p.findings, ctx.Err()
		default:
		}

		slog.Info("[*] Pipeline 阶段开始", "stage", stage.Name, "modules", len(stage.Modules), "targets", len(currentTargets))
		start := time.Now()

		profile := p.techDetector.Detect(currentTargets, p.findings)

		selectedModules := p.moduleCutter.CutModules(stage.Modules, profile, currentTargets)

		p.resourceMonitor.Adjust()

		var stageTargets []*Target

		if stage.Parallel {
			stageTargets = p.runParallel(ctx, selectedModules, currentTargets)
		} else {
			stageTargets = p.runSequential(ctx, selectedModules, currentTargets)
		}

		if len(stageTargets) > 0 {
			currentTargets = p.propagator.Propagate(currentTargets, stageTargets, p.findings)
		}

		slog.Info("[*] Pipeline 阶段完成",
			"stage", stage.Name,
			"duration", time.Since(start),
			"findings", len(p.findings),
			"new_targets", len(currentTargets),
		)
	}

	return p.findings, nil
}

func (p *Pipeline) runParallel(ctx context.Context, modules []ScanModule, targets []*Target) []*Target {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var newTargets []*Target

	for _, mod := range modules {
		wg.Add(1)
		m := mod
		p.pool.Submit(func() {
			defer wg.Done()

			result, err := m.Run(ctx, targets, nil)
			if err != nil {
				slog.Error("[!] 模块执行失败", "module", m.ID(), "error", err)
				return
			}
			if result == nil {
				return
			}

			mu.Lock()
			if result.Findings != nil {
				for _, f := range result.Findings {
					if !p.dedup.IsDuplicate(m.ID(), f) {
						p.findings = append(p.findings, f)
					}
				}
			}
			if result.Targets != nil {
				newTargets = append(newTargets, result.Targets...)
			}
			mu.Unlock()
		})
	}

	wg.Wait()
	return newTargets
}

func (p *Pipeline) runSequential(ctx context.Context, modules []ScanModule, targets []*Target) []*Target {
	var newTargets []*Target

	for _, mod := range modules {
		select {
		case <-ctx.Done():
			return newTargets
		default:
		}

		result, err := mod.Run(ctx, targets, nil)
		if err != nil {
			slog.Error("[!] 模块执行失败", "module", mod.ID(), "error", err)
			continue
		}
		if result == nil {
			continue
		}

		if result.Findings != nil {
			for _, f := range result.Findings {
				if !p.dedup.IsDuplicate(mod.ID(), f) {
					p.findings = append(p.findings, f)
				}
			}
		}
		if result.Targets != nil {
			newTargets = append(newTargets, result.Targets...)
		}
	}

	return newTargets
}

func (p *Pipeline) Shutdown() {
	p.pool.Shutdown()
}
