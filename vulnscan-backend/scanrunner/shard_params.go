package scanrunner

import (
	"strings"

	"vulnscan-backend/model"
)

func cloneJSONMap(m model.JSONMap) model.JSONMap {
	if m == nil {
		return nil
	}
	out := make(model.JSONMap, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// stripWorkerShardSchedulingParams 子任务参数中移除仅作用于「父任务分片决策」的键，避免子任务再次触发分片。
func stripWorkerShardSchedulingParams(m model.JSONMap) model.JSONMap {
	c := cloneJSONMap(m)
	if c != nil {
		delete(c, "worker_target_sharding")
		delete(c, "worker_shard_min_targets")
	}
	return c
}

func workerTargetShardingEnabled(params model.JSONMap) bool {
	if params == nil {
		return false
	}
	v, ok := params["worker_target_sharding"]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}
