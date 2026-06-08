package scanrunner

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

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
	var schedules []model.ScanSchedule
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

func (cs *CronScheduler) triggerSchedule(ctx context.Context, schedule *model.ScanSchedule) {
	templateID := schedule.TemplateID
	if templateID == "" {
		templateID = "full"
	}

	task := model.ScanTask{
		ID:           ulid.GenerateID(),
		Name:         schedule.Name + " (定时)",
		TemplateID:   templateID,
		TemplateName: schedule.TemplateName,
		Targets:      schedule.Targets,
		Parameters:   schedule.Config,
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
