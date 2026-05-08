package sitemonitor

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

type CronScheduler struct {
	db      *db.DB
	svc     *serviceMonitor
	cron    *cron.Cron
	mu      sync.RWMutex
	entries map[string]cron.EntryID // "taskID:dimension" -> cronEntryID
	cancel  context.CancelFunc
}

func NewCronScheduler(database *db.DB, svc *serviceMonitor) *CronScheduler {
	return &CronScheduler{
		db:      database,
		svc:     svc,
		cron:    cron.New(cron.WithSeconds(), cron.WithChain(cron.Recover(cron.DefaultLogger))),
		entries: make(map[string]cron.EntryID),
	}
}

func (cs *CronScheduler) session() *gorm.DB {
	s, _ := cs.db.GetDBSession()
	return s
}

func dimKey(taskID, dimension string) string {
	return fmt.Sprintf("%s:%s", taskID, dimension)
}

func (cs *CronScheduler) Start(ctx context.Context) {
	ctx, cs.cancel = context.WithCancel(ctx)
	cs.loadAllTasks()
	cs.cron.Start()
	go cs.updateNextRunTimes(ctx)
	slog.Info("[CronScheduler] started", "entries", len(cs.entries))
}

func (cs *CronScheduler) Stop() {
	if cs.cancel != nil {
		cs.cancel()
	}
	stopCtx := cs.cron.Stop()
	<-stopCtx.Done()
	slog.Info("[CronScheduler] stopped")
}

func (cs *CronScheduler) loadAllTasks() {
	var tasks []model.MonitorTask
	cs.session().Where("schedule_enabled = ? AND enabled = ?", true, true).Find(&tasks)
	for _, task := range tasks {
		cs.addTask(task)
	}
}

func (cs *CronScheduler) addTask(task model.MonitorTask) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.removeTaskEntriesLocked(task.ID)

	if !task.ScheduleEnabled || !task.Enabled {
		return
	}

	defaultCron := task.ScheduleCron
	if defaultCron == "" {
		defaultCron = "0 */30 * * * *"
	}
	jitter := task.ScheduleJitter
	if jitter < 0 {
		jitter = 0
	}
	taskID := task.ID

	registered := 0
	for _, dim := range model.MonitorAllDimensions {
		cfg := task.GetDimensionConfig(dim)
		if cfg == nil {
			continue
		}
		enabled, _ := cfg["enabled"].(bool)
		if !enabled {
			continue
		}

		dimCron, _ := cfg["cron"].(string)
		if dimCron == "" {
			dimCron = defaultCron
		}

		dimension := dim
		key := dimKey(taskID, dimension)

		entryID, err := cs.cron.AddFunc(dimCron, func() {
			if jitter > 0 {
				time.Sleep(time.Duration(rand.Intn(jitter)) * time.Second)
			}
			cs.executeDimension(taskID, dimension)
		})
		if err != nil {
			slog.Error("[CronScheduler] failed to add job",
				"task_id", taskID, "dimension", dimension, "cron", dimCron, "error", err)
			continue
		}

		cs.entries[key] = entryID
		registered++
		slog.Debug("[CronScheduler] dimension registered",
			"task_id", taskID, "dimension", dimension, "cron", dimCron)
	}

	if registered > 0 {
		slog.Info("[CronScheduler] task registered",
			"task_id", taskID, "dimensions", registered, "default_cron", defaultCron)
	}
}

func (cs *CronScheduler) executeDimension(taskID, dimension string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	execIDs, err := cs.svc.RunTask(ctx, taskID, []string{dimension})
	if err != nil {
		slog.Warn("[CronScheduler] dimension execution failed",
			"task_id", taskID, "dimension", dimension, "error", err)
		return
	}
	slog.Info("[CronScheduler] dimension dispatched",
		"task_id", taskID, "dimension", dimension, "executions", len(execIDs))
}

func (cs *CronScheduler) removeTaskEntriesLocked(taskID string) {
	prefix := taskID + ":"
	for key, entryID := range cs.entries {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			cs.cron.Remove(entryID)
			delete(cs.entries, key)
		}
	}
}

func (cs *CronScheduler) SyncTaskFromDB(taskID string) {
	var task model.MonitorTask
	if err := cs.session().Where("id = ?", taskID).First(&task).Error; err != nil {
		cs.RemoveTask(taskID)
		return
	}
	cs.addTask(task)
}

func (cs *CronScheduler) RemoveTask(taskID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.removeTaskEntriesLocked(taskID)
	slog.Info("[CronScheduler] task removed", "task_id", taskID)
}

func (cs *CronScheduler) ReloadAll() {
	cs.mu.Lock()
	for key, entryID := range cs.entries {
		cs.cron.Remove(entryID)
		delete(cs.entries, key)
	}
	cs.mu.Unlock()
	cs.loadAllTasks()
	slog.Info("[CronScheduler] reloaded all", "entries", len(cs.entries))
}

func (cs *CronScheduler) updateNextRunTimes(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cs.mu.RLock()
			nextRuns := map[string]time.Time{}
			for key, entryID := range cs.entries {
				entry := cs.cron.Entry(entryID)
				if entry.Next.IsZero() {
					continue
				}
				taskID := key[:len(key)-len(key)+len(key)]
				if idx := len(key) - 1; idx > 0 {
					for i := range key {
						if key[i] == ':' {
							taskID = key[:i]
							break
						}
					}
				}
				if cur, ok := nextRuns[taskID]; !ok || entry.Next.Before(cur) {
					nextRuns[taskID] = entry.Next
				}
			}
			cs.mu.RUnlock()

			for taskID, nextRun := range nextRuns {
				cs.session().Model(&model.MonitorTask{}).
					Where("id = ?", taskID).
					Update("next_run_at", nextRun)
			}
		}
	}
}

func (cs *CronScheduler) GetScheduleInfo() []map[string]any {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var result []map[string]any
	for key, entryID := range cs.entries {
		entry := cs.cron.Entry(entryID)
		taskID, dimension := "", ""
		for i := range key {
			if key[i] == ':' {
				taskID = key[:i]
				dimension = key[i+1:]
				break
			}
		}
		result = append(result, map[string]any{
			"task_id":   taskID,
			"dimension": dimension,
			"next_run":  entry.Next,
			"prev_run":  entry.Prev,
		})
	}
	return result
}

func (cs *CronScheduler) ActiveCount() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.entries)
}
