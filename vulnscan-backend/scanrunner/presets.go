package scanrunner

import (
	"fmt"
	"sort"
	"strings"

	"vulnscan-backend/model"
)

// EnginePresetInfo 供 GET /scan/engine-presets 与前端展示。
type EnginePresetInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

var enginePresetDefs = map[string]EnginePresetInfo{
	"auto": {
		Name:        "auto",
		Description: "按目标数量自动推导并发与速率（任务 parameters 可覆盖单项）。",
		Parameters:  map[string]interface{}{},
	},
	"conservative": {
		Name:        "conservative",
		Description: "降低全局请求速率并关闭 Interactsh OOB，适合脆弱环境或低带宽。",
		Parameters: map[string]interface{}{
			"rate_limit":                40,
			"nuclei_interactsh_disable": true,
			"poc_unmatched_fallback":    "skip",
		},
	},
	"distributed_safe": {
		Name:        "distributed_safe",
		Description: "多 Worker 分片时减轻 OOB 与总出站压力；仍允许任务参数覆盖。",
		Parameters: map[string]interface{}{
			"rate_limit":                60,
			"nuclei_interactsh_disable": true,
			"poc_unmatched_fallback":    "skip",
		},
	},
	"nuclei_oast_ready": {
		Name:        "nuclei_oast_ready",
		Description: "显式允许 Interactsh（需自建服务或环境变量 URL）；并略放宽轮询。",
		Parameters: map[string]interface{}{
			"nuclei_interactsh_disable":      false,
			"nuclei_interactsh_poll_seconds": 8,
		},
	},
}

// ScanEnginePreset 按名称返回预设参数字典（拷贝），未知名称返回 nil。
func ScanEnginePreset(name string) map[string]interface{} {
	key := strings.ToLower(strings.TrimSpace(name))
	def, ok := enginePresetDefs[key]
	if !ok || len(def.Parameters) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(def.Parameters))
	for k, v := range def.Parameters {
		out[k] = v
	}
	return out
}

// ListScanEnginePresets 返回全部内置预设（稳定排序）。
func ListScanEnginePresets() []EnginePresetInfo {
	names := make([]string, 0, len(enginePresetDefs))
	for n := range enginePresetDefs {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]EnginePresetInfo, 0, len(names))
	for _, n := range names {
		def := enginePresetDefs[n]
		cp := make(map[string]interface{}, len(def.Parameters))
		for k, v := range def.Parameters {
			cp[k] = v
		}
		def.Parameters = cp
		out = append(out, def)
	}
	return out
}

func enginePresetName(params model.JSONMap) string {
	if params == nil {
		return ""
	}
	v, ok := params["engine_preset"]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

// MergePresetWithParameters 先合并 engine_preset 对应键，再用任务 parameters 覆盖（并去掉 engine_preset 元键）。
func MergePresetWithParameters(params model.JSONMap) map[string]interface{} {
	out := make(map[string]interface{})
	if name := enginePresetName(params); name != "" {
		if preset := ScanEnginePreset(name); len(preset) > 0 {
			for k, v := range preset {
				out[k] = v
			}
		}
	}
	if params != nil {
		for k, v := range params {
			if k == "engine_preset" {
				continue
			}
			out[k] = v
		}
	}
	return out
}
