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
	stages   []PipelineStage
	pool     *WorkerPool
	limiter  *RateLimiter
	findings []*Finding
	mu       sync.Mutex
}

func NewPipeline(poolSize, globalRate, targetRate int) *Pipeline {
	return &Pipeline{
		pool:    NewWorkerPool(poolSize),
		limiter: NewRateLimiter(globalRate, targetRate),
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

		var stageTargets []*Target

		if stage.Parallel {
			stageTargets = p.runParallel(ctx, stage.Modules, currentTargets)
		} else {
			stageTargets = p.runSequential(ctx, stage.Modules, currentTargets)
		}

		if len(stageTargets) > 0 {
			currentTargets = append(currentTargets, stageTargets...)
		}

		slog.Info("[*] Pipeline 阶段完成",
			"stage", stage.Name,
			"duration", time.Since(start),
			"findings", len(p.findings),
			"new_targets", len(stageTargets),
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
				p.mu.Lock()
				p.findings = append(p.findings, result.Findings...)
				p.mu.Unlock()
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
			p.mu.Lock()
			p.findings = append(p.findings, result.Findings...)
			p.mu.Unlock()
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
