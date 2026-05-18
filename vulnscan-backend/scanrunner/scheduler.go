package scanrunner

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
	"vulnscan-backend/template/engine"
)

type Scheduler struct {
	db           *gorm.DB
	queue        *TaskQueue
	runners      map[string]*Runner
	mu           sync.Mutex
	maxParallel  int
	stopCh       chan struct{}
	wakeup       chan struct{}
	wg           sync.WaitGroup
	eventBus     *EventBus
	planResolver *PlanResolver
}

func New(db *gorm.DB, maxParallel int) *Scheduler {
	if maxParallel <= 0 {
		maxParallel = 5
	}
	factory := NewModuleFactory(db)
	return &Scheduler{
		db:           db,
		queue:        NewTaskQueue(),
		runners:      make(map[string]*Runner),
		maxParallel:  maxParallel,
		stopCh:       make(chan struct{}),
		wakeup:       make(chan struct{}, 1),
		eventBus:     NewEventBus(),
		planResolver: NewPlanResolver(factory),
	}
}

func (s *Scheduler) Start(ctx context.Context) {
	s.recoverFromDB(ctx)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.dispatchLoop(ctx)
	}()

	slog.Info("[Scheduler] 调度器启动",
		"max_parallel", s.maxParallel,
		"queue_size", s.queue.Len(),
	)
}

func (s *Scheduler) Stop() {
	close(s.stopCh)

	s.mu.Lock()
	for _, r := range s.runners {
		r.Cancel()
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("[Scheduler] 调度器已停止")
	case <-time.After(30 * time.Second):
		slog.Warn("[Scheduler] 调度器强制停止（超时）")
	}
}

// Enqueue adds a task to the in-memory priority queue and wakes the dispatcher.
func (s *Scheduler) Enqueue(task *model.ScanTask) {
	s.queue.Push(NewTaskItem(task))
	s.wake()
}

func (s *Scheduler) wake() {
	select {
	case s.wakeup <- struct{}{}:
	default:
	}
}

func (s *Scheduler) dispatchLoop(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-s.wakeup:
			s.drain(ctx)
		case <-ticker.C:
			s.drain(ctx)
		}
	}
}

// drain pops tasks from queue until no slots available or queue empty.
func (s *Scheduler) drain(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.mu.Lock()
		slots := s.maxParallel - len(s.runners)
		s.mu.Unlock()

		if slots <= 0 {
			return
		}

		item := s.queue.Pop()
		if item == nil {
			return
		}

		s.startTask(ctx, *item.Task)
	}
}

func (s *Scheduler) startTask(ctx context.Context, task model.ScanTask) {
	tmplInstance, err := s.resolveTemplate(task)
	if err != nil {
		slog.Error("[Scheduler] 模板解析失败", "task", task.ID, "template", task.TemplateID, "error", err)
		s.db.Model(&model.ScanTask{}).Where("id = ?", task.ID).
			Updates(map[string]interface{}{
				"status":    model.TaskStatusFailed,
				"error_msg": "模板解析失败: " + err.Error(),
			})
		if task.Type == model.TaskTypeAssetEnrich {
			task.Status = model.TaskStatusFailed
			CleanupAssetEnrichTask(s.db, &task)
		}
		return
	}

	now := time.Now()
	err = s.db.Model(&model.ScanTask{}).
		Where("id = ? AND status = ?", task.ID, model.TaskStatusQueued).
		Updates(map[string]interface{}{
			"status":     model.TaskStatusRunning,
			"started_at": &now,
		}).Error
	if err != nil {
		slog.Warn("[Scheduler] 更新任务状态失败", "task", task.ID, "error", err)
		return
	}

	runner := NewRunner(s.db, task, s.eventBus, tmplInstance, s.planResolver)
	runCtx, cancel := context.WithCancel(ctx)
	runner.cancelFn = cancel

	s.mu.Lock()
	s.runners[task.ID] = runner
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.runners, task.ID)
			s.mu.Unlock()
			s.eventBus.CloseTask(task.ID)
			s.wake()
		}()

		runner.Execute(runCtx)
	}()

	slog.Info("[Scheduler] 任务已启动",
		"task_id", task.ID,
		"name", task.Name,
		"template", task.TemplateID,
		"priority", task.Priority,
		"targets", len(task.Targets),
	)
}

func (s *Scheduler) resolveTemplate(task model.ScanTask) (*engine.TemplateInstance, error) {
	var tmplRecord model.ScanTemplate
	if err := s.db.Where("id = ? OR code = ?", task.TemplateID, task.TemplateID).First(&tmplRecord).Error; err != nil {
		return nil, err
	}

	tmpl, err := engine.ParseTemplate([]byte(tmplRecord.Content))
	if err != nil {
		return nil, err
	}

	params := make(map[string]interface{})
	for k, v := range task.Parameters {
		params[k] = v
	}

	return engine.Instantiate(tmpl, params)
}

// recoverFromDB loads queued tasks into in-memory queue at startup.
func (s *Scheduler) recoverFromDB(ctx context.Context) {
	var tasks []model.ScanTask
	err := s.db.WithContext(ctx).
		Where("status = ?", model.TaskStatusQueued).
		Where("(worker_id = '' OR worker_id IS NULL)").
		Order("priority DESC, created_at ASC").
		Find(&tasks).Error
	if err != nil {
		slog.Error("[Scheduler] 恢复任务失败", "error", err)
		return
	}

	for i := range tasks {
		s.queue.Push(NewTaskItem(&tasks[i]))
	}

	if len(tasks) > 0 {
		slog.Info("[Scheduler] 恢复待执行任务", "count", len(tasks))
		s.wake()
	}
}

func (s *Scheduler) CancelTask(taskID string) bool {
	if s.queue.Remove(taskID) {
		s.db.Model(&model.ScanTask{}).Where("id = ?", taskID).
			Update("status", model.TaskStatusCancelled)
		return true
	}

	s.mu.Lock()
	runner, ok := s.runners[taskID]
	s.mu.Unlock()

	if !ok {
		return false
	}

	runner.Cancel()
	return true
}

func (s *Scheduler) GetProgress(taskID string) *TaskProgress {
	s.mu.Lock()
	runner, ok := s.runners[taskID]
	s.mu.Unlock()

	if !ok {
		return nil
	}

	return runner.GetProgress()
}

func (s *Scheduler) ActiveTasks() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runners)
}

func (s *Scheduler) QueueLen() int {
	return s.queue.Len()
}

func (s *Scheduler) MaxParallel() int {
	return s.maxParallel
}

func (s *Scheduler) SubscribeEvents(taskID string) <-chan ScanEvent {
	return s.eventBus.Subscribe(taskID, 256)
}

func (s *Scheduler) UnsubscribeEvents(taskID string, ch <-chan ScanEvent) {
	s.eventBus.Unsubscribe(taskID, ch)
}

func (s *Scheduler) RunnerCacheHitRate() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var totalHits, totalMisses int64
	for _, r := range s.runners {
		if r.resultCache != nil {
			h, m := r.resultCache.Stats()
			totalHits += h
			totalMisses += m
		}
	}
	total := totalHits + totalMisses
	if total == 0 {
		return 0
	}
	return float64(totalHits) / float64(total)
}

func (s *Scheduler) CurrentAdaptiveConcurrency() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	maxConc := 0
	for _, r := range s.runners {
		if r.adaptive != nil {
			c := r.adaptive.CurrentConcurrency()
			if c > maxConc {
				maxConc = c
			}
		}
	}
	return maxConc
}
