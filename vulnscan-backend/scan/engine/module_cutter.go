package engine

import (
	"context"
	"log/slog"
	"sort"
)

type ModuleScore struct {
	Module ScanModule
	Score  float64
}

type ModuleStats struct {
	SuccessRate float64
	ExecCount   int
	AvgDuration float64
}

type SmartModuleCutter struct {
	threshold       float64
	historicalStats map[string]*ModuleStats
}

func NewSmartModuleCutter(threshold float64) *SmartModuleCutter {
	if threshold <= 0 {
		threshold = 1.0
	}
	return &SmartModuleCutter{
		threshold:       threshold,
		historicalStats: make(map[string]*ModuleStats),
	}
}

func (c *SmartModuleCutter) CutModules(modules []ScanModule, profile *AdvancedTechProfile, targets []*Target) []ScanModule {
	selected := make([]ModuleScore, 0, len(modules))

	for _, m := range modules {
		score := c.scoreModule(m, profile, targets)

		if score >= c.threshold {
			selected = append(selected, ModuleScore{Module: m, Score: score})
		}
	}

	sort.Slice(selected, func(i, j int) bool {
		return selected[i].Score > selected[j].Score
	})

	result := make([]ScanModule, 0, len(selected))
	for _, s := range selected {
		s.Module = &PriorityModule{Module: s.Module, Priority: s.Score}
		result = append(result, s.Module)
	}

	slog.Info("[ModuleCutter] 模块裁剪完成",
		"total", len(modules),
		"selected", len(result),
		"skipped", len(modules)-len(result),
	)

	return result
}

func (c *SmartModuleCutter) scoreModule(m ScanModule, profile *AdvancedTechProfile, targets []*Target) float64 {
	score := 1.0

	if matchesTech(m, profile.Stack) {
		score *= 2.0
	}

	if applicablePorts := c.getApplicablePorts(m); len(applicablePorts) > 0 {
		portMatchRatio := countPortMatches(targets, applicablePorts) / float64(len(targets))
		score *= (1 + portMatchRatio)
	}

	if stats := c.getHistoricalStats(m.ID()); stats.SuccessRate > 0 {
		score *= (0.5 + stats.SuccessRate)
	}

	if profile.Confidence < 0.5 {
		score *= 0.8
	}

	for _, skip := range profile.SkipModules {
		if m.ID() == skip {
			return 0
		}
	}

	for _, rec := range profile.RecommendModules {
		if m.ID() == rec {
			score *= 1.5
		}
	}

	for _, hp := range profile.HighPriority {
		if m.ID() == hp {
			score *= 2.0
		}
	}

	return score
}

func matchesTech(m ScanModule, tech TechStack) bool {
	category := m.Category()
	if category == "" {
		return false
	}

	techCategoryMap := map[TechStack][]string{
		TechPHP:    {"php", "wordpress", "laravel", "drupal"},
		TechJava:   {"java", "spring", "struts", "tomcat"},
		TechPython: {"python", "django", "flask"},
		TechNode:   {"nodejs", "express"},
		TechASPNET: {"asp", "dotnet", "iis"},
		TechRuby:   {"ruby", "rails"},
	}

	if categories, ok := techCategoryMap[tech]; ok {
		for _, c := range categories {
			if category == c {
				return true
			}
		}
	}

	return false
}

func (c *SmartModuleCutter) getApplicablePorts(m ScanModule) []int {
	if pm, ok := m.(interface{ ApplicablePorts() []int }); ok {
		return pm.ApplicablePorts()
	}
	return nil
}

func countPortMatches(targets []*Target, applicablePorts []int) float64 {
	if len(targets) == 0 || len(applicablePorts) == 0 {
		return 0
	}

	portSet := make(map[int]bool)
	for _, p := range applicablePorts {
		portSet[p] = true
	}

	var matchCount float64
	for _, t := range targets {
		if t.Port > 0 && portSet[t.Port] {
			matchCount++
		}
	}

	return matchCount
}

func (c *SmartModuleCutter) getHistoricalStats(moduleID string) *ModuleStats {
	if stats, ok := c.historicalStats[moduleID]; ok {
		return stats
	}
	return &ModuleStats{}
}

func (c *SmartModuleCutter) UpdateStats(moduleID string, success bool, duration float64) {
	stats, ok := c.historicalStats[moduleID]
	if !ok {
		stats = &ModuleStats{}
		c.historicalStats[moduleID] = stats
	}

	stats.ExecCount++
	if success {
		stats.SuccessRate = (stats.SuccessRate*float64(stats.ExecCount-1) + 1.0) / float64(stats.ExecCount)
	} else {
		stats.SuccessRate = (stats.SuccessRate * float64(stats.ExecCount-1)) / float64(stats.ExecCount)
	}
	stats.AvgDuration = (stats.AvgDuration*float64(stats.ExecCount-1) + duration) / float64(stats.ExecCount)
}

type PriorityModule struct {
	Module   ScanModule
	Priority float64
}

func (pm *PriorityModule) ID() string {
	return pm.Module.ID()
}

func (pm *PriorityModule) Name() string {
	return pm.Module.Name()
}

func (pm *PriorityModule) Category() string {
	return pm.Module.Category()
}

func (pm *PriorityModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	return pm.Module.Run(ctx, targets, config)
}

func (pm *PriorityModule) SetPriority(p float64) {
	pm.Priority = p
}

func init() {
	slog.Debug("[SmartModuleCutter] 智能模块裁剪器就绪")
}
