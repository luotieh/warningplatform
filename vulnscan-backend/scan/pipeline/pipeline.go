package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"vulnscan-backend/scan/engine"
)

// Stage 流水线阶段
type Stage struct {
	Name    string
	Modules []engine.ScanModule
	Config  map[string]interface{}
	Filter  func(findings []*engine.Finding) []*engine.Target
}

// Pipeline 扫描流水线 — 模块间自动数据联动
type Pipeline struct {
	stages   []Stage
	registry *engine.ModuleRegistry
}

func New(registry *engine.ModuleRegistry) *Pipeline {
	return &Pipeline{registry: registry}
}

func (p *Pipeline) AddStage(s Stage) {
	p.stages = append(p.stages, s)
}

// PipelineResult 流水线执行结果
type PipelineResult struct {
	Stages   []StageResult
	Total    int
	Duration time.Duration
}

type StageResult struct {
	Name     string
	Findings []*engine.Finding
	Targets  int
	Duration time.Duration
}

// Run 执行整个流水线
func (p *Pipeline) Run(ctx context.Context, initialTargets []*engine.Target) (*PipelineResult, error) {
	start := time.Now()
	pr := &PipelineResult{}
	currentTargets := initialTargets

	for i, stage := range p.stages {
		select {
		case <-ctx.Done():
			return pr, ctx.Err()
		default:
		}

		slog.Info("[Pipeline] 开始阶段",
			"stage", i+1,
			"name", stage.Name,
			"targets", len(currentTargets),
			"modules", len(stage.Modules),
		)

		stageStart := time.Now()
		sr := StageResult{
			Name:    stage.Name,
			Targets: len(currentTargets),
		}

		var mu sync.Mutex
		var wg sync.WaitGroup

		for _, mod := range stage.Modules {
			wg.Add(1)
			go func(m engine.ScanModule) {
				defer wg.Done()

				result, err := m.Run(ctx, currentTargets, stage.Config)
				if err != nil {
					slog.Warn("[Pipeline] 模块执行失败",
						"module", m.ID(),
						"error", err,
					)
					return
				}

				mu.Lock()
				sr.Findings = append(sr.Findings, result.Findings...)
				mu.Unlock()

				slog.Info("[Pipeline] 模块完成",
					"module", m.ID(),
					"findings", len(result.Findings),
					"duration", result.Duration,
				)
			}(mod)
		}

		wg.Wait()
		sr.Duration = time.Since(stageStart)
		pr.Stages = append(pr.Stages, sr)
		pr.Total += len(sr.Findings)

		if stage.Filter != nil && i < len(p.stages)-1 {
			newTargets := stage.Filter(sr.Findings)
			if len(newTargets) > 0 {
				currentTargets = append(currentTargets, newTargets...)
				currentTargets = dedup(currentTargets)
			}
			slog.Info("[Pipeline] 阶段过滤",
				"stage", stage.Name,
				"new_targets", len(newTargets),
				"total_targets", len(currentTargets),
			)
		}
	}

	pr.Duration = time.Since(start)
	slog.Info("[Pipeline] 流水线完成",
		"stages", len(p.stages),
		"total_findings", pr.Total,
		"duration", pr.Duration,
	)

	return pr, nil
}

// --- 预置 Filter 函数 ---

// URLsToTargets 将爬虫发现的 URL Finding 转为 Target
func URLsToTargets(findings []*engine.Finding) []*engine.Target {
	var targets []*engine.Target
	seen := make(map[string]struct{})

	for _, f := range findings {
		if f.Type != "url" && f.Type != "script" {
			continue
		}
		urlStr := ""
		if f.Data != nil {
			urlStr = f.Data["url"]
		}
		if urlStr == "" {
			continue
		}
		if _, ok := seen[urlStr]; ok {
			continue
		}
		seen[urlStr] = struct{}{}
		targets = append(targets, &engine.Target{URL: urlStr})
	}
	return targets
}

// SubdomainsToTargets 将子域名 Finding 转为 Target
func SubdomainsToTargets(findings []*engine.Finding) []*engine.Target {
	var targets []*engine.Target
	seen := make(map[string]struct{})

	for _, f := range findings {
		if f.Type != "subdomain" && f.Type != "domain" {
			continue
		}
		host := ""
		if f.Data != nil {
			host = f.Data["subdomain"]
			if host == "" {
				host = f.Data["domain"]
			}
		}
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		targets = append(targets, &engine.Target{Host: host})
	}
	return targets
}

// IPsToTargets 将 IP Finding 转为 Target
func IPsToTargets(findings []*engine.Finding) []*engine.Target {
	var targets []*engine.Target
	seen := make(map[string]struct{})

	for _, f := range findings {
		if f.Data == nil {
			continue
		}
		ip := f.Data["ip"]
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		targets = append(targets, &engine.Target{IP: ip})
	}
	return targets
}

// PortsToTargets 将端口扫描 Finding 转为带端口的 Target
func PortsToTargets(findings []*engine.Finding) []*engine.Target {
	var targets []*engine.Target
	seen := make(map[string]struct{})

	for _, f := range findings {
		if f.Data == nil {
			continue
		}
		ip := f.Data["ip"]
		port := f.Data["port"]
		if ip == "" || port == "" {
			continue
		}
		key := ip + ":" + port
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		p := 0
		for _, c := range port {
			p = p*10 + int(c-'0')
		}

		scheme := "http"
		if p == 443 || p == 8443 {
			scheme = "https"
		}

		targets = append(targets, &engine.Target{
			IP:   ip,
			Port: p,
			URL:  fmt.Sprintf("%s://%s:%s", scheme, ip, port),
		})
	}
	return targets
}

func dedup(targets []*engine.Target) []*engine.Target {
	seen := make(map[string]struct{})
	var result []*engine.Target
	for _, t := range targets {
		key := t.Host + "|" + t.IP + "|" + t.URL
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, t)
		}
	}
	return result
}
