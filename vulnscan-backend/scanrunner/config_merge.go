package scanrunner

import (
	"strings"

	"vulnscan-backend/model"
	"vulnscan-backend/scan/core"
)

// ModuleConfigFor 见 scan/core/config_merge.go
func ModuleConfigFor(moduleID string, global map[string]interface{}) map[string]interface{} {
	return core.ModuleConfigFor(moduleID, global)
}

// ApplyDerivedAndPreset 合并 engine_preset，并在 auto/未指定时自动推导性能参数（手动键优先）。
func ApplyDerivedAndPreset(params model.JSONMap) map[string]interface{} {
	out := MergePresetWithParameters(params)
	preset := enginePresetName(params)
	if preset != "" && preset != "auto" {
		return out
	}
	targetCount := 1
	if raw, ok := params["target_count"]; ok {
		switch n := raw.(type) {
		case int:
			targetCount = n
		case float64:
			targetCount = int(n)
		case int64:
			targetCount = int(n)
		}
	}
	derived := DeriveScanParameters(targetCount)
	for k, v := range derived {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
	return out
}

func countTargets(targets []string) int {
	n := 0
	for _, t := range targets {
		if strings.TrimSpace(t) != "" {
			n++
		}
	}
	if n == 0 {
		return 1
	}
	return n
}
