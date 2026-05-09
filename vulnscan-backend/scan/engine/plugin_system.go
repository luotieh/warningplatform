package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type PluginType string

const (
	PluginWeb     PluginType = "web"
	PluginNetwork PluginType = "network"
	PluginConfig  PluginType = "config"
	PluginCVE     PluginType = "cve"
)

type PluginInfo struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Type        PluginType `json:"type"`
	Severity    string     `json:"severity"`
	CVEIDs      []string   `json:"cve_ids,omitempty"`
	CWEIDs      []string   `json:"cwe_ids,omitempty"`
	CVSSScore   float64    `json:"cvss_score,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
}

type Plugin interface {
	Info() PluginInfo
	Run(ctx context.Context, target *Target) ([]*Finding, error)
}

type PluginRegistry struct {
	plugins map[string]Plugin
	mu      sync.RWMutex
}

func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		plugins: make(map[string]Plugin),
	}
}

func (r *PluginRegistry) Register(p Plugin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins[p.Info().ID] = p
	slog.Info("[Plugin] 注册插件", "id", p.Info().ID, "name", p.Info().Name, "type", p.Info().Type)
}

func (r *PluginRegistry) Get(id string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[id]
	return p, ok
}

func (r *PluginRegistry) List() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		list = append(list, p)
	}
	return list
}

func (r *PluginRegistry) ListByType(t PluginType) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		if p.Info().Type == t {
			list = append(list, p)
		}
	}
	return list
}

type PluginScanner struct {
	registry    *PluginRegistry
	concurrency int
}

func NewPluginScanner(registry *PluginRegistry, concurrency int) *PluginScanner {
	if concurrency <= 0 {
		concurrency = 10
	}
	return &PluginScanner{
		registry:    registry,
		concurrency: concurrency,
	}
}

func (s *PluginScanner) RunAll(ctx context.Context, targets []*Target) ([]*Finding, error) {
	plugins := s.registry.List()
	return s.runPlugins(ctx, plugins, targets)
}

func (s *PluginScanner) RunByType(ctx context.Context, t PluginType, targets []*Target) ([]*Finding, error) {
	plugins := s.registry.ListByType(t)
	return s.runPlugins(ctx, plugins, targets)
}

func (s *PluginScanner) RunSelected(ctx context.Context, pluginIDs []string, targets []*Target) ([]*Finding, error) {
	plugins := make([]Plugin, 0, len(pluginIDs))
	for _, id := range pluginIDs {
		if p, ok := s.registry.Get(id); ok {
			plugins = append(plugins, p)
		}
	}
	return s.runPlugins(ctx, plugins, targets)
}

func (s *PluginScanner) runPlugins(ctx context.Context, plugins []Plugin, targets []*Target) ([]*Finding, error) {
	if len(plugins) == 0 || len(targets) == 0 {
		return nil, nil
	}

	var mu sync.Mutex
	var allFindings []*Finding
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.concurrency)

	for _, target := range targets {
		for _, plugin := range plugins {
			wg.Add(1)
			sem <- struct{}{}
			go func(t *Target, p Plugin) {
				defer wg.Done()
				defer func() { <-sem }()

				select {
				case <-ctx.Done():
					return
				default:
				}

				findings, err := p.Run(ctx, t)
				if err != nil {
					slog.Debug("[Plugin] 插件执行失败",
						"plugin", p.Info().ID,
						"target", t.Host,
						"error", err,
					)
					return
				}

				if len(findings) > 0 {
					mu.Lock()
					for _, f := range findings {
						f.ModuleID = p.Info().ID
						if f.Type == "" {
							f.Type = string(p.Info().Type)
						}
						if f.Severity == "" {
							f.Severity = p.Info().Severity
						}
						if len(f.CVEIDs) == 0 {
							f.CVEIDs = p.Info().CVEIDs
						}
						if len(f.CWEIDs) == 0 {
							f.CWEIDs = p.Info().CWEIDs
						}
						if f.CVSSScore == 0 {
							f.CVSSScore = p.Info().CVSSScore
						}
					}
					allFindings = append(allFindings, findings...)
					mu.Unlock()
				}
			}(target, plugin)
		}
	}

	wg.Wait()

	slog.Info("[Plugin] 插件扫描完成",
		"plugins", len(plugins),
		"targets", len(targets),
		"findings", len(allFindings),
	)

	return allFindings, nil
}

type PluginModuleAdapter struct {
	registry *PluginRegistry
	scanner  *PluginScanner
}

func NewPluginModuleAdapter(registry *PluginRegistry, concurrency int) *PluginModuleAdapter {
	return &PluginModuleAdapter{
		registry: registry,
		scanner:  NewPluginScanner(registry, concurrency),
	}
}

func (a *PluginModuleAdapter) ID() string       { return "plugin-scanner" }
func (a *PluginModuleAdapter) Name() string     { return "Plugin Scanner" }
func (a *PluginModuleAdapter) Category() string { return "plugin" }

func (a *PluginModuleAdapter) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	start := now()

	pluginIDs, _ := config["plugin_ids"].([]string)
	pluginType, _ := config["plugin_type"].(string)

	var findings []*Finding
	var err error

	if len(pluginIDs) > 0 {
		findings, err = a.scanner.RunSelected(ctx, pluginIDs, targets)
	} else if pluginType != "" {
		findings, err = a.scanner.RunByType(ctx, PluginType(pluginType), targets)
	} else {
		findings, err = a.scanner.RunAll(ctx, targets)
	}

	if err != nil {
		return nil, fmt.Errorf("plugin scanner: %w", err)
	}

	return &ModuleResult{
		ModuleID: a.ID(),
		Findings: findings,
		Duration: now().Sub(start),
	}, nil
}

func now() time.Time {
	return time.Now()
}
