package sitemonitor

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/db"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

type schedulerProfile struct {
	maxConcurrency int
	taskTimeout    time.Duration
}

func detectSchedulerProfile() schedulerProfile {
	cpus := runtime.NumCPU()

	profile := schedulerProfile{
		maxConcurrency: cpus * 10,
		taskTimeout:    120 * time.Second,
	}
	if profile.maxConcurrency < 20 {
		profile.maxConcurrency = 20
	}
	if profile.maxConcurrency > 100 {
		profile.maxConcurrency = 100
	}

	if cpus >= 16 {
		profile.taskTimeout = 180 * time.Second
	} else if cpus >= 8 {
		profile.taskTimeout = 150 * time.Second
	}

	if v := os.Getenv("MONITOR_MAX_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			profile.maxConcurrency = n
		}
	}
	if v := os.Getenv("MONITOR_TASK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			profile.taskTimeout = d
		}
	}

	slog.Info("[Scheduler] auto-detected profile",
		"cpus", cpus,
		"max_concurrency", profile.maxConcurrency,
		"task_timeout", profile.taskTimeout,
	)
	return profile
}

// scheduleEntry 内存中的调度条目，不再依赖 robfig/cron 的 entry。
type scheduleEntry struct {
	scope     string // "target" or "path"
	entityID  string
	dimension string
	cronExpr  string
	nextRun   time.Time
	schedule  cron.Schedule // 用于计算 nextRun
}

type CronScheduler struct {
	db      *db.DB
	svc     *serviceMonitor
	mu      sync.RWMutex
	entries map[string]*scheduleEntry // key -> entry
	sem     chan struct{}
	profile schedulerProfile
	cancel  context.CancelFunc
}

func NewCronScheduler(database *db.DB, svc *serviceMonitor) *CronScheduler {
	p := detectSchedulerProfile()
	return &CronScheduler{
		db:      database,
		svc:     svc,
		entries: make(map[string]*scheduleEntry),
		sem:     make(chan struct{}, p.maxConcurrency),
		profile: p,
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

// parseCronExpr 解析 6 段 cron 表达式
var cronParser = cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

func parseCronExpr(expr string) (cron.Schedule, error) {
	return cronParser.Parse(expr)
}

func (cs *CronScheduler) Start(ctx context.Context) {
	ctx, cs.cancel = context.WithCancel(ctx)
	cs.loadAllSchedules()
	go cs.dispatchLoop(ctx)
	go cs.syncNextRunTimesLoop(ctx)
	go cs.logSchedulerStats(ctx)
	slog.Info("[Scheduler] started", "entries", len(cs.entries))
}

func (cs *CronScheduler) Stop() {
	if cs.cancel != nil {
		cs.cancel()
	}
	slog.Info("[Scheduler] stopped")
}

func (cs *CronScheduler) logSchedulerStats(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			active := cs.ActiveCount()
			semLen := len(cs.sem)
			semCap := cap(cs.sem)
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			slog.Info("[Scheduler] stats",
				"entries", active,
				"concurrency", fmt.Sprintf("%d/%d", semLen, semCap),
				"goroutines", runtime.NumGoroutine(),
				"heap_mb", m.HeapAlloc/1024/1024,
			)
		}
	}
}

// dispatchLoop 核心调度循环：每 30 秒扫描到期条目，批量分发。
func (cs *CronScheduler) dispatchLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// 启动后等一会让系统稳定
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cs.dispatchDueEntries(ctx)
		}
	}
}

// dispatchDueEntries 找出所有 nextRun <= now 的条目，限流分发。
func (cs *CronScheduler) dispatchDueEntries(ctx context.Context) {
	now := time.Now()

	cs.mu.Lock()
	var due []*scheduleEntry
	for _, entry := range cs.entries {
		if !entry.nextRun.IsZero() && !entry.nextRun.After(now) {
			due = append(due, entry)
			entry.nextRun = entry.schedule.Next(now)
		}
	}
	cs.mu.Unlock()

	if len(due) == 0 {
		return
	}

	// 随机打乱顺序，避免总是同一批先执行
	rand.Shuffle(len(due), func(i, j int) { due[i], due[j] = due[j], due[i] })

	slog.Info("[Scheduler] dispatching due entries", "count", len(due))

	var wg sync.WaitGroup
	for _, entry := range due {
		select {
		case <-ctx.Done():
			return
		case cs.sem <- struct{}{}:
		}

		wg.Add(1)
		go func(e *scheduleEntry) {
			defer func() {
				<-cs.sem
				wg.Done()
			}()

			dispatchCtx, cancel := context.WithTimeout(ctx, cs.profile.taskTimeout)
			defer cancel()

			var outcome *contract.RunTaskOutcome
			var err error
			switch e.scope {
			case "target":
				outcome, err = cs.svc.RunTarget(dispatchCtx, e.entityID, []string{e.dimension})
			case "path":
				outcome, err = cs.svc.RunPathTask(dispatchCtx, e.entityID, []string{e.dimension})
			}

			if err != nil {
				if !isBusyErr(err) {
					errMsg := err.Error()
					if strings.Contains(errMsg, "不存在") {
						slog.Info("[Scheduler] removing stale entry",
							"scope", e.scope, "id", e.entityID, "dim", e.dimension)
						cs.mu.Lock()
						delete(cs.entries, scheduleKey(e.scope, e.entityID, e.dimension))
						cs.mu.Unlock()
					} else {
						slog.Warn("[Scheduler] dispatch failed",
							"scope", e.scope, "id", e.entityID, "dim", e.dimension, "error", err)
					}
				}
				return
			}
			if outcome != nil && len(outcome.ExecutionIDs) > 0 {
				slog.Info("[Scheduler] dispatched",
					"scope", e.scope, "id", e.entityID, "dim", e.dimension,
					"executions", len(outcome.ExecutionIDs))
			}
		}(entry)
	}

	wg.Wait()
}

func (cs *CronScheduler) loadAllSchedules() {
	var targets []model.MonitorTarget
	cs.session().Where("enabled = ? AND schedule_enabled = ?", true, true).Find(&targets)
	slog.Info("[Scheduler] loading targets", "count", len(targets))
	for _, t := range targets {
		cs.addTarget(t)
	}

	var paths []model.MonitorPathTask
	cs.session().Where("enabled = ? AND schedule_enabled = ?", true, true).Find(&paths)
	slog.Info("[Scheduler] loading path tasks", "count", len(paths))
	for _, p := range paths {
		cs.addPathTask(p)
	}
	slog.Info("[Scheduler] all schedules loaded", "total_entries", len(cs.entries))
}

func (cs *CronScheduler) registerDimensions(
	scope, entityID, defaultCron string,
	_ int, // jitter param kept for API compat, no longer used
	dimensions []string,
	getCfg func(string) model.JSONMap,
	_ func(context.Context, string) (*contract.RunTaskOutcome, error), // run param kept for API compat
) {
	if defaultCron == "" {
		defaultCron = "0 */30 * * * *"
	}
	now := time.Now()
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

		sched, err := parseCronExpr(dimCron)
		if err != nil {
			slog.Error("[Scheduler] invalid cron expr",
				"scope", scope, "id", entityID, "dim", dim, "cron", dimCron, "error", err)
			continue
		}

		key := scheduleKey(scope, entityID, dim)
		cs.entries[key] = &scheduleEntry{
			scope:     scope,
			entityID:  entityID,
			dimension: dim,
			cronExpr:  dimCron,
			schedule:  sched,
			nextRun:   sched.Next(now),
		}
		registered++
	}

	if registered > 0 {
		slog.Debug("[Scheduler] entity registered",
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
	cs.registerDimensions("target", target.ID, target.ScheduleCron, target.ScheduleJitter, model.MonitorTargetDimensions,
		target.GetDimensionConfig, nil)
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
	cs.registerDimensions("path", pt.ID, pt.ScheduleCron, pt.ScheduleJitter, model.MonitorPathDimensions,
		pt.GetDimensionConfig, nil)
}

func (cs *CronScheduler) removeScopeEntriesLocked(scope, id string) {
	prefix := scope + ":" + id + ":"
	for key := range cs.entries {
		if strings.HasPrefix(key, prefix) {
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
	cs.entries = make(map[string]*scheduleEntry)
	cs.mu.Unlock()
	cs.loadAllSchedules()
}

// syncNextRunTimesLoop 定期将内存中的 nextRun 批量写入 DB。
func (cs *CronScheduler) syncNextRunTimesLoop(ctx context.Context) {
	entryCount := cs.ActiveCount()
	interval := 2 * time.Minute
	if entryCount > 20000 {
		interval = 5 * time.Minute
	} else if entryCount > 10000 {
		interval = 3 * time.Minute
	}
	slog.Info("[Scheduler] syncNextRunTimes interval", "entries", entryCount, "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cs.batchUpdateNextRunTimes()
		}
	}
}

func (cs *CronScheduler) batchUpdateNextRunTimes() {
	cs.mu.RLock()
	targetNext := map[string]time.Time{}
	pathNext := map[string]time.Time{}
	for _, entry := range cs.entries {
		if entry.nextRun.IsZero() {
			continue
		}
		switch entry.scope {
		case "target":
			if cur, ok := targetNext[entry.entityID]; !ok || entry.nextRun.Before(cur) {
				targetNext[entry.entityID] = entry.nextRun
			}
		case "path":
			if cur, ok := pathNext[entry.entityID]; !ok || entry.nextRun.Before(cur) {
				pathNext[entry.entityID] = entry.nextRun
			}
		}
	}
	cs.mu.RUnlock()

	batchUpdateNextRun(cs.session(), &model.MonitorTarget{}, targetNext)
	batchUpdateNextRun(cs.session(), &model.MonitorPathTask{}, pathNext)
}

// batchUpdateNextRun 使用 CASE-WHEN 批量更新 next_run_at。
func batchUpdateNextRun(session *gorm.DB, tableModel any, nextMap map[string]time.Time) {
	if len(nextMap) == 0 {
		return
	}

	const batchSize = 500
	ids := make([]string, 0, len(nextMap))
	for id := range nextMap {
		ids = append(ids, id)
	}

	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[i:end]

		var caseBuilder strings.Builder
		caseBuilder.WriteString("CASE id ")
		args := make([]any, 0, len(batch)*2+len(batch))
		for _, id := range batch {
			caseBuilder.WriteString("WHEN ? THEN ? ")
			args = append(args, id, nextMap[id])
		}
		caseBuilder.WriteString("END")

		batchIDs := make([]string, len(batch))
		copy(batchIDs, batch)
		args = append(args, batchIDs)

		session.Model(tableModel).
			Where("id IN ?", args[len(args)-1]).
			Update("next_run_at", gorm.Expr(caseBuilder.String(), args[:len(args)-1]...))
	}
}

func (cs *CronScheduler) GetScheduleInfo() []map[string]any {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	var result []map[string]any
	for _, entry := range cs.entries {
		result = append(result, map[string]any{
			"scope":     entry.scope,
			"id":        entry.entityID,
			"dimension": entry.dimension,
			"cron":      entry.cronExpr,
			"next_run":  entry.nextRun,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		ti := result[i]["next_run"].(time.Time)
		tj := result[j]["next_run"].(time.Time)
		return ti.Before(tj)
	})
	return result
}

func (cs *CronScheduler) ActiveCount() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.entries)
}
