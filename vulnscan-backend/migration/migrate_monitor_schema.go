package migration

import (
	"log/slog"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

func init() {
	Register("006_monitor_target_schema", "站点监测：目标/路径任务表结构，移除 monitor_executions.task_id", func(tx *gorm.DB) error {
		if tx.Migrator().HasTable("monitor_tasks") {
			if err := tx.Migrator().DropTable("monitor_tasks"); err != nil {
				slog.Warn("[Migration] 删除 monitor_tasks 失败", "error", err)
			}
		}

		if err := tx.AutoMigrate(
			&model.MonitorTarget{},
			&model.MonitorPathTask{},
			&model.MonitorCrawlJob{},
			&model.MonitorExecution{},
		); err != nil {
			return err
		}

		if tx.Migrator().HasTable("monitor_executions") && tx.Migrator().HasColumn("monitor_executions", "task_id") {
			if err := tx.Migrator().DropColumn("monitor_executions", "task_id"); err != nil {
				slog.Warn("[Migration] 删除 monitor_executions.task_id 失败，尝试兼容写入", "error", err)
			}
		}

		return nil
	})
}
