package sitemonitor

import (
	"fmt"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// MonitorRunContext 一次监测执行所需的解析结果。
type MonitorRunContext struct {
	Target   *model.MonitorTarget
	PathTask *model.MonitorPathTask
	Endpoint *ResolvedEndpoint
}

func loadMonitorRunContext(db *gorm.DB, exec *model.MonitorExecution) (*MonitorRunContext, error) {
	if exec == nil {
		return nil, fmt.Errorf("execution is nil")
	}
	var target model.MonitorTarget
	tid := exec.TargetID
	if tid == "" && exec.PathTaskID != "" {
		var pt model.MonitorPathTask
		if err := db.Select("target_id").First(&pt, "id = ?", exec.PathTaskID).Error; err != nil {
			return nil, err
		}
		tid = pt.TargetID
	}
	if tid == "" {
		return nil, fmt.Errorf("target_id missing on execution")
	}
	if err := db.First(&target, "id = ?", tid).Error; err != nil {
		return nil, err
	}
	ctx := &MonitorRunContext{Target: &target}
	if exec.PathTaskID != "" {
		var pt model.MonitorPathTask
		if err := db.First(&pt, "id = ?", exec.PathTaskID).Error; err != nil {
			return nil, err
		}
		ctx.PathTask = &pt
		ep, err := ResolvePathTaskURL(&target, &pt)
		if err != nil {
			return nil, err
		}
		ctx.Endpoint = ep
		return ctx, nil
	}
	ep, err := ResolveTargetRootURL(&target)
	if err != nil {
		return nil, err
	}
	ctx.Endpoint = ep
	return ctx, nil
}

func pathConfigForRun(pt *model.MonitorPathTask, dimension string) (model.JSONMap, error) {
	cfg := pt.GetDimensionConfig(dimension)
	if cfg != nil && len(cfg) > 0 {
		return cfg, nil
	}
	seed, ok := model.MonitorDefaultConfigSeeds[dimension]
	if !ok {
		return nil, fmt.Errorf("维度 %s 未配置", dimension)
	}
	out := model.JSONMap{}
	for k, v := range seed {
		out[k] = v
	}
	return out, nil
}

func targetConfigForRun(t *model.MonitorTarget, dimension string) (model.JSONMap, error) {
	cfg := t.GetDimensionConfig(dimension)
	if cfg != nil && len(cfg) > 0 {
		return cfg, nil
	}
	seed, ok := model.MonitorDefaultConfigSeeds[dimension]
	if !ok {
		return nil, fmt.Errorf("维度 %s 未配置", dimension)
	}
	out := model.JSONMap{}
	for k, v := range seed {
		out[k] = v
	}
	return out, nil
}
