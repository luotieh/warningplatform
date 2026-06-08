package scanrunner

import (
	"fmt"
	"time"

	"code.yt-security.com/public/scanengine/core"
	"vulnscan-backend/template/engine"
)

type PlanResolver struct {
	factory *ModuleFactory
}

func NewPlanResolver(factory *ModuleFactory) *PlanResolver {
	return &PlanResolver{factory: factory}
}

func (pr *PlanResolver) Resolve(instance *engine.TemplateInstance) ([]stageGroup, error) {
	if instance == nil {
		return nil, fmt.Errorf("template instance is nil")
	}

	stages := make([]stageGroup, 0, len(instance.Stages))
	for _, rs := range instance.Stages {
		modules, err := pr.factory.BuildMany(rs.ModuleIDs)
		if err != nil {
			return nil, fmt.Errorf("阶段 '%s': %w", rs.Name, err)
		}
		if len(modules) == 0 {
			continue
		}

		sg := stageGroup{
			name:      rs.Name,
			modules:   modules,
			parallel:  rs.Parallel,
			condition: rs.Condition,
			dependsOn: rs.DependsOn,
			config:    rs.Config,
			timeout:   rs.Timeout,
		}
		stages = append(stages, sg)
	}

	if len(stages) == 0 {
		return nil, fmt.Errorf("模板未产生任何可执行阶段")
	}
	return stages, nil
}

func DefaultTimeout(stages []stageGroup) time.Duration {
	total := 0
	for _, s := range stages {
		total += len(s.modules)
	}
	if total <= 4 {
		return 2 * time.Minute
	}
	return time.Duration(total) * 30 * time.Second
}

func mergeConfig(base, overlay map[string]interface{}) map[string]interface{} {
	if len(overlay) == 0 {
		return base
	}
	merged := make(map[string]interface{}, len(base)+len(overlay))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range overlay {
		merged[k] = v
	}
	return merged
}

// StageModuleIDs returns all module IDs across all stages (for progress tracking).
func StageModuleIDs(stages []stageGroup) []string {
	var ids []string
	for _, s := range stages {
		for _, m := range s.modules {
			ids = append(ids, m.ID())
		}
	}
	return ids
}

// TotalModules returns the total number of modules across all stages.
func TotalModules(stages []stageGroup) int {
	total := 0
	for _, s := range stages {
		total += len(s.modules)
	}
	return total
}

// StageContext holds results from completed stages for condition evaluation.
type StageContext struct {
	CompletedStages map[string]StageResult
	Params          map[string]interface{}
}

type StageResult struct {
	Findings []*core.Finding
	Targets  []*core.Target
}
