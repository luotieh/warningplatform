package scheduler

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// CronScheduler periodically checks ScanSchedule entries and creates ScanTask instances.
type CronScheduler struct {
	db        *gorm.DB
	scheduler *Scheduler
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

func NewCronScheduler(db *gorm.DB, scheduler *Scheduler) *CronScheduler {
	return &CronScheduler{
		db:        db,
		scheduler: scheduler,
		stopCh:    make(chan struct{}),
	}
}

func (cs *CronScheduler) Start(ctx context.Context) {
	cs.wg.Add(1)
	go func() {
		defer cs.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		slog.Info("[CronScheduler] 定时任务调度器已启动")

		for {
			select {
			case <-ctx.Done():
				return
			case <-cs.stopCh:
				return
			case <-ticker.C:
				cs.check(ctx)
			}
		}
	}()
}

func (cs *CronScheduler) Stop() {
	close(cs.stopCh)
	cs.wg.Wait()
	slog.Info("[CronScheduler] 已停止")
}

func (cs *CronScheduler) check(ctx context.Context) {
	var schedules []ScanSchedule
	err := cs.db.WithContext(ctx).
		Where("enabled = ? AND (next_run_at IS NULL OR next_run_at <= ?)", true, time.Now()).
		Find(&schedules).Error
	if err != nil {
		slog.Warn("[CronScheduler] 查询定时任务失败", "error", err)
		return
	}

	for i := range schedules {
		cs.triggerSchedule(ctx, &schedules[i])
	}
}

func (cs *CronScheduler) triggerSchedule(ctx context.Context, schedule *ScanSchedule) {
	config := model.JSONMap{
		"profile": schedule.Profile,
	}
	if len(schedule.Modules) > 0 {
		mods := make([]interface{}, len(schedule.Modules))
		for i, m := range schedule.Modules {
			mods[i] = m
		}
		config["modules"] = mods
	}

	task := model.ScanTask{
		ID:           qulid.GenerateID(),
		Name:         schedule.Name + " (定时)",
		Type:         schedule.Profile,
		Targets:      schedule.Targets,
		Config:       config,
		Parameters:   schedule.Parameters,
		Priority:     5,
		Status:       model.TaskStatusQueued,
		TotalTargets: len(schedule.Targets),
		ScheduleID:   schedule.ID,
		CreatedBy:    schedule.CreatedBy,
		OrganizeID:   schedule.OrganizeID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := cs.db.WithContext(ctx).Create(&task).Error; err != nil {
		slog.Warn("[CronScheduler] 创建任务失败", "schedule", schedule.ID, "error", err)
		return
	}

	cs.scheduler.Enqueue(&task)

	now := time.Now()
	nextRun := computeNextRun(schedule.CronExpr, now)

	cs.db.WithContext(ctx).Model(schedule).Updates(map[string]interface{}{
		"last_run_at": &now,
		"next_run_at": nextRun,
	})

	slog.Info("[CronScheduler] 定时任务触发",
		"schedule_id", schedule.ID,
		"task_id", task.ID,
		"targets", len(task.Targets),
		"next_run", nextRun,
	)
}

// computeNextRun parses a simplified cron expression and returns the next run time.
// Supports: "every Nh" (every N hours), "every Nm" (every N minutes), "every Nd" (every N days)
// Or standard: "HH:MM" for daily at specific time.
func computeNextRun(expr string, from time.Time) *time.Time {
	expr = strings.TrimSpace(strings.ToLower(expr))

	if strings.HasPrefix(expr, "every ") {
		part := strings.TrimPrefix(expr, "every ")
		part = strings.TrimSpace(part)

		if strings.HasSuffix(part, "h") {
			if n, err := strconv.Atoi(strings.TrimSuffix(part, "h")); err == nil && n > 0 {
				next := from.Add(time.Duration(n) * time.Hour)
				return &next
			}
		}
		if strings.HasSuffix(part, "m") {
			if n, err := strconv.Atoi(strings.TrimSuffix(part, "m")); err == nil && n > 0 {
				next := from.Add(time.Duration(n) * time.Minute)
				return &next
			}
		}
		if strings.HasSuffix(part, "d") {
			if n, err := strconv.Atoi(strings.TrimSuffix(part, "d")); err == nil && n > 0 {
				next := from.Add(time.Duration(n) * 24 * time.Hour)
				return &next
			}
		}
	}

	if len(expr) == 5 && expr[2] == ':' {
		hour, errH := strconv.Atoi(expr[:2])
		minute, errM := strconv.Atoi(expr[3:])
		if errH == nil && errM == nil && hour >= 0 && hour < 24 && minute >= 0 && minute < 60 {
			next := time.Date(from.Year(), from.Month(), from.Day(), hour, minute, 0, 0, from.Location())
			if !next.After(from) {
				next = next.Add(24 * time.Hour)
			}
			return &next
		}
	}

	fallback := from.Add(24 * time.Hour)
	return &fallback
}
