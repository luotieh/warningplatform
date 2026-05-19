package sitemonitor

import (
	"fmt"
	"strconv"
	"strings"

	"vulnscan-backend/model"
)

// configEnabled 判断维度是否启用；配置存在但未写 enabled 时视为启用。
func configEnabled(cfg model.JSONMap) bool {
	if cfg == nil {
		return false
	}
	v, ok := cfg["enabled"]
	if !ok {
		return true
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

// cronExprFromDimensionConfig 从维度配置解析 cron 表达式（秒级，robfig/cron 六段）。
func cronExprFromDimensionConfig(cfg model.JSONMap) string {
	if cfg == nil {
		return ""
	}
	if c, ok := cfg["cron"].(string); ok && strings.TrimSpace(c) != "" {
		return strings.TrimSpace(c)
	}
	if mins := intFromAny(cfg["cycle_minutes"]); mins > 0 {
		if mins > 59 {
			mins = 59
		}
		return fmt.Sprintf("0 */%d * * * *", mins)
	}
	cycleType, _ := cfg["cycle_type"].(string)
	cycleTime, _ := cfg["cycle_time"].(string)
	if cycleType == "daily" && cycleTime != "" {
		parts := strings.Split(cycleTime, ":")
		h, m := 0, 0
		if len(parts) >= 1 {
			h, _ = strconv.Atoi(strings.TrimSpace(parts[0]))
		}
		if len(parts) >= 2 {
			m, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		}
		return fmt.Sprintf("0 %d %d * * *", m, h)
	}
	return ""
}

// entityHasScheduledDimensions 判断实体是否至少有一个已启用且带周期的维度。
func entityHasScheduledDimensions(dimensions []string, getCfg func(string) model.JSONMap) bool {
	for _, dim := range dimensions {
		cfg := getCfg(dim)
		if cfg == nil || !configEnabled(cfg) {
			continue
		}
		if cronExprFromDimensionConfig(cfg) != "" {
			return true
		}
	}
	return false
}

func pathTaskHasScheduledDimensions(pt *model.MonitorPathTask) bool {
	if pt == nil {
		return false
	}
	return entityHasScheduledDimensions(model.MonitorPathDimensions, pt.GetDimensionConfig)
}

func targetHasScheduledDimensions(t *model.MonitorTarget) bool {
	if t == nil {
		return false
	}
	return entityHasScheduledDimensions(model.MonitorTargetDimensions, t.GetDimensionConfig)
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(n))
		return i
	}
	return 0
}
