package schedule

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/scanrunner"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type CronRunner struct {
	db        *gorm.DB
	scheduler *scanrunner.Scheduler
	mu        sync.Mutex
	stopCh    chan struct{}
	ticker    *time.Ticker
}

func NewCronRunner(db *gorm.DB, sched *scanrunner.Scheduler) *CronRunner {
	return &CronRunner{
		db:        db,
		scheduler: sched,
		stopCh:    make(chan struct{}),
	}
}

func (cr *CronRunner) Start(ctx context.Context) {
	cr.ticker = time.NewTicker(30 * time.Second)
	go func() {
		cr.check()
		for {
			select {
			case <-cr.ticker.C:
				cr.check()
			case <-cr.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	slog.Info("[+] Cron 调度器已启动，检查间隔 30s")
}

func (cr *CronRunner) Stop() {
	close(cr.stopCh)
	if cr.ticker != nil {
		cr.ticker.Stop()
	}
}

func (cr *CronRunner) check() {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	var schedules []model.ScanSchedule
	now := time.Now()
	if err := cr.db.Where("enabled = ? AND (next_run_at IS NULL OR next_run_at <= ?)", true, now).
		Find(&schedules).Error; err != nil {
		slog.Error("[Cron] 查询调度任务失败", "error", err)
		return
	}

	for _, s := range schedules {
		if s.Status == model.ScheduleStatusRunning {
			if s.LastTaskID != "" {
				var task model.ScanTask
				if err := cr.db.Where("id = ?", s.LastTaskID).First(&task).Error; err == nil {
					if task.Status == model.TaskStatusRunning || task.Status == model.TaskStatusPending || task.Status == model.TaskStatusQueued {
						continue
					}
				}
			}
		}

		cr.executeSchedule(s)
	}
}

func (cr *CronRunner) executeSchedule(s model.ScanSchedule) {
	taskID := qulid.GenerateID()
	now := time.Now()

	templateID := s.TemplateID
	if templateID == "" {
		templateID = "full"
	}

	task := model.ScanTask{
		ID:           taskID,
		Name:         s.Name + " (定时)",
		TemplateID:   templateID,
		TemplateName: s.TemplateName,
		Targets:      s.Targets,
		Parameters:   s.Config,
		Priority:     3,
		Status:       model.TaskStatusQueued,
		TotalTargets: len(s.Targets),
		ScheduleID:   s.ID,
		CreatedBy:    s.CreatedBy,
		OrganizeID:   s.OrganizeID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := cr.db.Create(&task).Error; err != nil {
		slog.Error("[Cron] 创建定时任务失败", "schedule", s.ID, "error", err)
		return
	}

	cr.scheduler.Enqueue(&task)

	nextRun := calcNextRun(s)
	cr.db.Model(&model.ScanSchedule{}).Where("id = ?", s.ID).Updates(map[string]any{
		"status":       model.ScheduleStatusRunning,
		"last_run_at":  &now,
		"next_run_at":  nextRun,
		"last_task_id": taskID,
		"run_count":    gorm.Expr("run_count + 1"),
	})

	slog.Info("[Cron] 定时任务已触发", "schedule", s.Name, "task_id", taskID, "next_run", nextRun)
}

func (cr *CronRunner) RunNow(id string) (string, error) {
	var item model.ScanSchedule
	if err := cr.db.Where("id = ?", id).First(&item).Error; err != nil {
		return "", err
	}

	taskID := qulid.GenerateID()
	now := time.Now()

	templateID := item.TemplateID
	if templateID == "" {
		templateID = "full"
	}

	task := model.ScanTask{
		ID:           taskID,
		Name:         item.Name + " (手动触发)",
		TemplateID:   templateID,
		TemplateName: item.TemplateName,
		Targets:      item.Targets,
		Parameters:   item.Config,
		Priority:     5,
		Status:       model.TaskStatusQueued,
		TotalTargets: len(item.Targets),
		ScheduleID:   item.ID,
		CreatedBy:    item.CreatedBy,
		OrganizeID:   item.OrganizeID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := cr.db.Create(&task).Error; err != nil {
		return "", err
	}

	cr.scheduler.Enqueue(&task)

	cr.db.Model(&model.ScanSchedule{}).Where("id = ?", id).Updates(map[string]any{
		"last_task_id": taskID,
		"run_count":    gorm.Expr("run_count + 1"),
	})

	return taskID, nil
}

func calcNextRun(s model.ScanSchedule) *time.Time {
	now := time.Now()
	var next time.Time

	switch s.ScheduleType {
	case model.ScheduleTypeInterval:
		if s.IntervalMin <= 0 {
			s.IntervalMin = 60
		}
		next = now.Add(time.Duration(s.IntervalMin) * time.Minute)

	case model.ScheduleTypeDaily:
		next = now.Add(24 * time.Hour)

	case model.ScheduleTypeWeekly:
		next = now.Add(7 * 24 * time.Hour)

	case model.ScheduleTypeMonthly:
		next = now.AddDate(0, 1, 0)

	case model.ScheduleTypeCron:
		parsed := parseCronNext(s.CronExpr, now)
		if parsed != nil {
			next = *parsed
		} else {
			next = now.Add(24 * time.Hour)
		}

	default:
		next = now.Add(24 * time.Hour)
	}

	return &next
}

func parseCronNext(expr string, after time.Time) *time.Time {
	// Minimal cron: support "HH:MM" daily format and common presets
	switch expr {
	case "@hourly":
		t := after.Add(1 * time.Hour).Truncate(time.Hour)
		return &t
	case "@daily", "@midnight":
		t := time.Date(after.Year(), after.Month(), after.Day()+1, 0, 0, 0, 0, after.Location())
		return &t
	case "@weekly":
		days := (7 - int(after.Weekday())) % 7
		if days == 0 {
			days = 7
		}
		t := time.Date(after.Year(), after.Month(), after.Day()+days, 0, 0, 0, 0, after.Location())
		return &t
	}

	if len(expr) == 5 && expr[2] == ':' {
		h := int(expr[0]-'0')*10 + int(expr[1]-'0')
		m := int(expr[3]-'0')*10 + int(expr[4]-'0')
		t := time.Date(after.Year(), after.Month(), after.Day(), h, m, 0, 0, after.Location())
		if !t.After(after) {
			t = t.Add(24 * time.Hour)
		}
		return &t
	}

	return nil
}
