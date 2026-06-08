package sitemonitor

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/db"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

type CronScheduler struct {
	db      *db.DB
	svc     *serviceMonitor
	cron    *cron.Cron
	mu      sync.RWMutex
	entries map[string]cron.EntryID // scopeKey -> entryID
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

func scheduleKey(scope, id, dimension string) string {
	return fmt.Sprintf("%s:%s:%s", scope, id, dimension)
}

func parseScheduleKey(key string) (scope, id, dimension string) {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) == 3 {
		return parts[0], parts[1], parts[2]
	}
	return "", "", ""
}

func (cs *CronScheduler) Start(ctx context.Context) {
	ctx, cs.cancel = context.WithCancel(ctx)
	cs.loadAllSchedules()
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

func (cs *CronScheduler) loadAllSchedules() {
	var targets []model.MonitorTarget
	cs.session().Where("enabled = ?", true).Find(&targets)
	for _, t := range targets {
		cs.addTarget(t)
	}
	var paths []model.MonitorPathTask
	cs.session().Where("enabled = ?", true).Find(&paths)
	for _, p := range paths {
		cs.addPathTask(p)
	}
}

func (cs *CronScheduler) registerDimensions(
	scope, entityID, defaultCron string,
	jitter int,
	dimensions []string,
	getCfg func(string) model.JSONMap,
	run func(context.Context, string) (*contract.RunTaskOutcome, error),
) {
	if defaultCron == "" {
		defaultCron = "0 */30 * * * *"
	}
	if jitter < 0 {
		jitter = 0
	}
	registered := 0
	for _, dim := range dimensions {
		cfg := getCfg(dim)
		if cfg == nil || !configEnabled(cfg) {
			continue
		}
		dimCron := cronExprFromDimensionConfig(cfg)
		if dimCron == "" {
			dimCron = defaultCron
		}
		key := scheduleKey(scope, entityID, dim)
		dimension := dim
		entryID, err := cs.cron.AddFunc(dimCron, func() {
			if jitter > 0 {
				time.Sleep(time.Duration(rand.Intn(jitter)) * time.Second)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			outcome, err := run(ctx, dimension)
			if err != nil {
				slog.Warn("[CronScheduler] scheduled run failed",
					"scope", scope, "id", entityID, "dimension", dimension, "error", err)
				return
			}
			slog.Info("[CronScheduler] scheduled run dispatched",
				"scope", scope, "id", entityID, "dimension", dimension, "executions", len(outcome.ExecutionIDs))
		})
		if err != nil {
			slog.Error("[CronScheduler] failed to add job",
				"scope", scope, "id", entityID, "dimension", dimension, "cron", dimCron, "error", err)
			continue
		}
		cs.entries[key] = entryID
		registered++
	}
	if registered > 0 {
		slog.Info("[CronScheduler] entity registered",
			"scope", scope, "id", entityID, "dimensions", registered)
	}
}

func (cs *CronScheduler) addTarget(target model.MonitorTarget) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.removeScopeEntriesLocked("target", target.ID)
	if !target.Enabled {
		return
	}
	if !target.ScheduleEnabled && targetHasScheduledDimensions(&target) {
		target.ScheduleEnabled = true
		cs.session().Model(&model.MonitorTarget{}).Where("id = ?", target.ID).Update("schedule_enabled", true)
	}
	if !target.ScheduleEnabled {
		return
	}
	t := target
	cs.registerDimensions("target", t.ID, t.ScheduleCron, t.ScheduleJitter, model.MonitorTargetDimensions,
		t.GetDimensionConfig,
		func(ctx context.Context, dim string) (*contract.RunTaskOutcome, error) {
			return cs.svc.RunTarget(ctx, t.ID, []string{dim})
		},
	)
}

func (cs *CronScheduler) addPathTask(pt model.MonitorPathTask) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.removeScopeEntriesLocked("path", pt.ID)
	if !pt.Enabled {
		return
	}
	if !pt.ScheduleEnabled && pathTaskHasScheduledDimensions(&pt) {
		pt.ScheduleEnabled = true
		cs.session().Model(&model.MonitorPathTask{}).Where("id = ?", pt.ID).Update("schedule_enabled", true)
	}
	if !pt.ScheduleEnabled {
		return
	}
	p := pt
	cs.registerDimensions("path", p.ID, p.ScheduleCron, p.ScheduleJitter, model.MonitorPathDimensions,
		p.GetDimensionConfig,
		func(ctx context.Context, dim string) (*contract.RunTaskOutcome, error) {
			return cs.svc.RunPathTask(ctx, p.ID, []string{dim})
		},
	)
}

func (cs *CronScheduler) removeScopeEntriesLocked(scope, id string) {
	prefix := scope + ":" + id + ":"
	for key, entryID := range cs.entries {
		if strings.HasPrefix(key, prefix) {
			cs.cron.Remove(entryID)
			delete(cs.entries, key)
		}
	}
}

func (cs *CronScheduler) SyncTargetFromDB(targetID string) {
	var target model.MonitorTarget
	if err := cs.session().Where("id = ?", targetID).First(&target).Error; err != nil {
		cs.RemoveTarget(targetID)
		return
	}
	cs.addTarget(target)
}

func (cs *CronScheduler) SyncPathTaskFromDB(pathTaskID string) {
	var pt model.MonitorPathTask
	if err := cs.session().Where("id = ?", pathTaskID).First(&pt).Error; err != nil {
		cs.RemovePathTask(pathTaskID)
		return
	}
	cs.addPathTask(pt)
}

func (cs *CronScheduler) RemoveTarget(targetID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.removeScopeEntriesLocked("target", targetID)
}

func (cs *CronScheduler) RemovePathTask(pathTaskID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.removeScopeEntriesLocked("path", pathTaskID)
}

// 兼容旧调用名
func (cs *CronScheduler) SyncTaskFromDB(id string) { cs.SyncPathTaskFromDB(id) }
func (cs *CronScheduler) RemoveTask(id string)     { cs.RemovePathTask(id) }

func (cs *CronScheduler) ReloadAll() {
	cs.mu.Lock()
	for key, entryID := range cs.entries {
		cs.cron.Remove(entryID)
		delete(cs.entries, key)
	}
	cs.mu.Unlock()
	cs.loadAllSchedules()
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
			targetNext := map[string]time.Time{}
			pathNext := map[string]time.Time{}
			for key, entryID := range cs.entries {
				entry := cs.cron.Entry(entryID)
				if entry.Next.IsZero() {
					continue
				}
				scope, id, _ := parseScheduleKey(key)
				switch scope {
				case "target":
					if cur, ok := targetNext[id]; !ok || entry.Next.Before(cur) {
						targetNext[id] = entry.Next
					}
				case "path":
					if cur, ok := pathNext[id]; !ok || entry.Next.Before(cur) {
						pathNext[id] = entry.Next
					}
				}
			}
			cs.mu.RUnlock()
			for id, next := range targetNext {
				cs.session().Model(&model.MonitorTarget{}).Where("id = ?", id).Update("next_run_at", next)
			}
			for id, next := range pathNext {
				cs.session().Model(&model.MonitorPathTask{}).Where("id = ?", id).Update("next_run_at", next)
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
		scope, id, dimension := parseScheduleKey(key)
		result = append(result, map[string]any{
			"scope":     scope,
			"id":        id,
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
