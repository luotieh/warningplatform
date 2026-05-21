package bundle

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

// Module 将多个子扫描模块合并为一个对外模块，发现项仍保留子模块 ID。
type Module struct {
	id        string
	name      string
	category  string
	children  []core.ScanModule
	parallel  int
	logPrefix string
}

func New(id, name, category string, parallel int, children []core.ScanModule) *Module {
	if parallel <= 0 {
		parallel = 4
	}
	filtered := make([]core.ScanModule, 0, len(children))
	for _, c := range children {
		if c != nil {
			filtered = append(filtered, c)
		}
	}
	return &Module{
		id:        id,
		name:      name,
		category:  category,
		children:  filtered,
		parallel:  parallel,
		logPrefix: "[" + id + "]",
	}
}

func (m *Module) ID() string       { return m.id }
func (m *Module) Name() string     { return m.name }
func (m *Module) Category() string { return m.category }

func (m *Module) Params() []core.ModuleParam {
	var params []core.ModuleParam
	switch m.id {
	case "host_discover":
		params = append(params, PortRangeParam())
	case "web_vuln_scan":
		params = append(params, core.VulnVerificationParam())
	default:
		// 其他组合模块无额外暴露项；子模块并行度由引擎自适应，不在 UI 展示以免误导。
	}
	return params
}

func (m *Module) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.id}

	if len(m.children) == 0 {
		return result, nil
	}

	bundleCfg := core.ModuleConfigFor(m.id, config)
	parallel := m.parallel
	if v := core.GetConfigInt(bundleCfg, "parallel", 0); v > 0 {
		parallel = v
	}
	if v := core.GetConfigInt(bundleCfg, "concurrency", 0); v > 0 {
		parallel = v
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)

	children := m.children
	if m.id == "host_discover" {
		children = filterHostDiscoverChildren(m.id, m.children, bundleCfg)
	}

	for _, child := range children {
		wg.Add(1)
		sem <- struct{}{}
		go func(mod core.ScanModule) {
			defer wg.Done()
			defer func() { <-sem }()

			childStart := time.Now()
			slog.Info(m.logPrefix+" 子模块开始", "module", mod.ID())

			childCfg := core.ModuleConfigFor(mod.ID(), config)
			applyBundleInheritance(m.id, bundleCfg, childCfg, mod.ID())
			modResult, err := mod.Run(ctx, targets, childCfg)
			if err != nil {
				slog.Warn(m.logPrefix+" 子模块执行失败", "module", mod.ID(), "error", err, "duration", time.Since(childStart).Round(time.Millisecond))
				return
			}
			if modResult == nil {
				slog.Info(m.logPrefix+" 子模块完成", "module", mod.ID(), "findings", 0, "duration", time.Since(childStart).Round(time.Millisecond))
				return
			}
			slog.Info(m.logPrefix+" 子模块完成", "module", mod.ID(),
				"findings", len(modResult.Findings), "duration", time.Since(childStart).Round(time.Millisecond))
			mu.Lock()
			if len(modResult.Findings) > 0 {
				result.Findings = append(result.Findings, modResult.Findings...)
			}
			if len(modResult.Targets) > 0 {
				result.Targets = append(result.Targets, modResult.Targets...)
			}
			mu.Unlock()
		}(child)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	slog.Info(m.logPrefix+" 组合模块完成",
		"children", len(m.children),
		"findings", len(result.Findings),
		"duration", result.Duration.Round(time.Millisecond),
	)
	return result, nil
}
