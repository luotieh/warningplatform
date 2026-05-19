package sitemonitor

import (
	"context"
	"encoding/json"
	"log/slog"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// 维度 config_json 中与自动转安全事件相关的字段。
const (
	cfgIncidentAutoEnabled       = "incident_auto_enabled"
	cfgIncidentOnUnavailable     = "incident_on_unavailable"
	cfgIncidentMaxResponseTimeMS = "incident_max_response_time_ms"
	cfgIncidentMinMatchCount     = "incident_min_match_count"
	cfgIncidentMinFileCount      = "incident_min_file_count"
	cfgIncidentMinDiffCount      = "incident_min_diff_count"
	cfgIncidentMinBlacklinkCount = "incident_min_blacklink_count"
	cfgIncidentOnHijack          = "incident_on_hijack"
)

// ShouldAutoCreateIncident 根据执行结果与有效维度配置判断是否自动创建安全事件。
func ShouldAutoCreateIncident(exec *model.MonitorExecution, cfg model.JSONMap) bool {
	if exec == nil || !exec.HasIssue || exec.Status == "failed" {
		return false
	}
	if !configBool(cfg, cfgIncidentAutoEnabled) {
		return false
	}
	ok := meetsIncidentThreshold(exec.Dimension, exec.ResultJSON, cfg)
	if !ok {
		slog.Debug("[MonitorBridge] 监测有问题但未达自动转事件阈值",
			"execution_id", exec.ID, "dimension", exec.Dimension)
	}
	return ok
}

// ResolveIncidentConfig 合并默认配置（DB/种子）< 目标 < 路径任务。
func ResolveIncidentConfig(ctx context.Context, db *gorm.DB, exec *model.MonitorExecution) model.JSONMap {
	if exec == nil {
		return nil
	}
	cfg := loadDefaultDimensionConfig(ctx, db, exec.Dimension)

	targetID := exec.TargetID
	var pathTask *model.MonitorPathTask
	if exec.PathTaskID != "" && db != nil {
		var pt model.MonitorPathTask
		if err := db.WithContext(ctx).First(&pt, "id = ?", exec.PathTaskID).Error; err == nil {
			pathTask = &pt
			if targetID == "" {
				targetID = pt.TargetID
			}
		}
	}
	if targetID != "" && db != nil {
		var t model.MonitorTarget
		if err := db.WithContext(ctx).First(&t, "id = ?", targetID).Error; err == nil {
			if overlay := t.GetDimensionConfig(exec.Dimension); len(overlay) > 0 {
				cfg = mergeJSONMap(cfg, overlay)
			}
		}
	}
	if pathTask != nil {
		if overlay := pathTask.GetDimensionConfig(exec.Dimension); len(overlay) > 0 {
			cfg = mergeJSONMap(cfg, overlay)
		}
	}
	return cfg
}

func loadDefaultDimensionConfig(ctx context.Context, db *gorm.DB, dimension string) model.JSONMap {
	out := model.JSONMap{}
	if seed, ok := model.MonitorDefaultConfigSeeds[dimension]; ok {
		for k, v := range seed {
			out[k] = v
		}
	}
	if db == nil {
		return out
	}
	var row model.MonitorDefaultConfig
	if err := db.WithContext(ctx).Where("dimension = ?", dimension).First(&row).Error; err == nil && row.ConfigJSON != nil {
		for k, v := range row.ConfigJSON {
			out[k] = v
		}
	}
	return out
}

func mergeJSONMap(base, overlay model.JSONMap) model.JSONMap {
	if base == nil && overlay == nil {
		return model.JSONMap{}
	}
	out := model.JSONMap{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

func configBool(cfg model.JSONMap, key string) bool {
	if cfg == nil {
		return false
	}
	v, ok := cfg[key]
	if !ok {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case int:
		return t != 0
	case string:
		return t == "true" || t == "1" || t == "yes"
	default:
		return false
	}
}

func configInt(cfg model.JSONMap, key string, fallback int) int {
	if cfg == nil {
		return fallback
	}
	if v, ok := cfg[key]; ok {
		if n := intFromAny(v); n >= 0 {
			return n
		}
	}
	return fallback
}

func meetsIncidentThreshold(dimension, resultJSON string, cfg model.JSONMap) bool {
	var m map[string]any
	if resultJSON != "" {
		_ = json.Unmarshal([]byte(resultJSON), &m)
	}
	if m == nil {
		m = map[string]any{}
	}

	switch dimension {
	case "availability":
		onUnavailable := true
		if cfg != nil {
			if _, ok := cfg[cfgIncidentOnUnavailable]; ok {
				onUnavailable = configBool(cfg, cfgIncidentOnUnavailable)
			}
		}
		available, _ := m["available"].(bool)
		rt := intFromAny(m["response_time_ms"])
		maxRT := configInt(cfg, cfgIncidentMaxResponseTimeMS, 0)
		if onUnavailable && !available {
			return true
		}
		if maxRT > 0 && rt >= maxRT {
			return true
		}
		return false

	case "sensitive_word":
		min := configInt(cfg, cfgIncidentMinMatchCount, 1)
		if min < 1 {
			min = 1
		}
		cnt := intFromAny(m["total_matches"])
		if cnt < jsonArrayLen(m, "matches") {
			cnt = jsonArrayLen(m, "matches")
		}
		if cnt == 0 && jsonBoolMap(m, "has_hit") {
			cnt = 1
		}
		return cnt >= min

	case "sensitive_file":
		min := configInt(cfg, cfgIncidentMinFileCount, 1)
		if min < 1 {
			min = 1
		}
		cnt := jsonArrayLen(m, "files")
		if n := jsonArrayLen(m, "matches"); n > cnt {
			cnt = n
		}
		if cnt == 0 && jsonBoolMap(m, "has_hit") {
			cnt = 1
		}
		return cnt >= min

	case "tamper":
		min := configInt(cfg, cfgIncidentMinDiffCount, 1)
		if min < 1 {
			min = 1
		}
		if !jsonBoolMap(m, "tampered") {
			return false
		}
		diff := intFromAny(m["diff_count"])
		if diff == 0 {
			diff = jsonArrayLen(m, "changes")
		}
		if diff == 0 {
			diff = 1
		}
		return diff >= min

	case "blacklink":
		min := configInt(cfg, cfgIncidentMinBlacklinkCount, 1)
		if min < 1 {
			min = 1
		}
		cnt := jsonArrayLen(m, "blacklink_matches") + jsonArrayLen(m, "backdoor_findings")
		if cnt == 0 && (jsonBoolMap(m, "has_black") || jsonBoolMap(m, "has_hit")) {
			cnt = 1
		}
		return cnt >= min

	case "domain_hijack":
		onHijack := true
		if cfg != nil {
			if _, ok := cfg[cfgIncidentOnHijack]; ok {
				onHijack = configBool(cfg, cfgIncidentOnHijack)
			}
		}
		return onHijack && jsonBoolMap(m, "hijacked")

	default:
		return true
	}
}

func jsonBoolMap(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func jsonArrayLen(m map[string]any, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch arr := v.(type) {
	case []any:
		return len(arr)
	case []map[string]any:
		return len(arr)
	default:
		return 0
	}
}
