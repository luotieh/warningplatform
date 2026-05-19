package migration

import (
	"fmt"
	"strconv"
	"strings"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

func init() {
	Register("008_monitor_schedule_enabled", "站点监测：为已配置周期的任务开启 schedule_enabled", func(tx *gorm.DB) error {
		if tx.Migrator().HasTable("monitor_path_tasks") {
			var paths []model.MonitorPathTask
			if err := tx.Where("enabled = ?", true).Find(&paths).Error; err == nil {
				for _, pt := range paths {
					if !pt.ScheduleEnabled && migratePathTaskHasSchedule(&pt) {
						_ = tx.Model(&pt).Update("schedule_enabled", true).Error
					}
				}
			}
		}
		if tx.Migrator().HasTable("monitor_targets") {
			var targets []model.MonitorTarget
			if err := tx.Where("enabled = ?", true).Find(&targets).Error; err == nil {
				for _, t := range targets {
					if !t.ScheduleEnabled && migrateTargetHasSchedule(&t) {
						_ = tx.Model(&t).Update("schedule_enabled", true).Error
					}
				}
			}
		}
		return nil
	})
}

func migratePathTaskHasSchedule(pt *model.MonitorPathTask) bool {
	for _, dim := range model.MonitorPathDimensions {
		if migrateDimSchedulable(pt.GetDimensionConfig(dim)) {
			return true
		}
	}
	return false
}

func migrateTargetHasSchedule(t *model.MonitorTarget) bool {
	for _, dim := range model.MonitorTargetDimensions {
		if migrateDimSchedulable(t.GetDimensionConfig(dim)) {
			return true
		}
	}
	return false
}

func migrateDimSchedulable(cfg model.JSONMap) bool {
	if cfg == nil {
		return false
	}
	if v, ok := cfg["enabled"]; ok {
		switch t := v.(type) {
		case bool:
			if !t {
				return false
			}
		case float64:
			if t == 0 {
				return false
			}
		}
	}
	return migrateCronFromCfg(cfg) != ""
}

func migrateCronFromCfg(cfg model.JSONMap) string {
	if c, ok := cfg["cron"].(string); ok && strings.TrimSpace(c) != "" {
		return strings.TrimSpace(c)
	}
	if mins := migrateIntFromAny(cfg["cycle_minutes"]); mins > 0 {
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

func migrateIntFromAny(v any) int {
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
