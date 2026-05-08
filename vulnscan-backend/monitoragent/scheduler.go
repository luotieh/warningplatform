package monitoragent

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Scheduler struct {
	engines       map[string]Engine
	pageService   *PageService
	maxConcurrent int
	taskTimeout   time.Duration

	running  atomic.Int32
	queued   atomic.Int32
	sem      chan struct{}
	wg       sync.WaitGroup
	onResult func(*TaskResult)
}

func NewScheduler(ps *PageService, maxConcurrent int, taskTimeout time.Duration) *Scheduler {
	if maxConcurrent <= 0 {
		maxConcurrent = 5
	}
	if taskTimeout <= 0 {
		taskTimeout = 5 * time.Minute
	}
	return &Scheduler{
		engines:       make(map[string]Engine),
		pageService:   ps,
		maxConcurrent: maxConcurrent,
		taskTimeout:   taskTimeout,
		sem:           make(chan struct{}, maxConcurrent),
	}
}

func (s *Scheduler) RegisterEngine(e Engine) {
	s.engines[e.Name()] = e
}

func (s *Scheduler) SetResultCallback(fn func(*TaskResult)) {
	s.onResult = fn
}

func (s *Scheduler) RunningCount() int  { return int(s.running.Load()) }
func (s *Scheduler) QueuedCount() int   { return int(s.queued.Load()) }
func (s *Scheduler) MaxConcurrent() int { return s.maxConcurrent }

func (s *Scheduler) Submit(task *TaskMessage) {
	s.queued.Add(1)
	s.wg.Add(1)
	go s.execute(task)
}

func (s *Scheduler) SubmitBatch(tasks []TaskMessage) {
	for i := range tasks {
		s.Submit(&tasks[i])
	}
}

func (s *Scheduler) execute(task *TaskMessage) {
	defer s.wg.Done()

	s.sem <- struct{}{}
	s.queued.Add(-1)
	s.running.Add(1)
	defer func() {
		<-s.sem
		s.running.Add(-1)
	}()

	result := &TaskResult{
		ExecutionID: task.ExecutionID,
		TaskID:      task.TaskID,
		Dimension:   task.Dimension,
		URL:         task.URL,
		StartedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	engine, ok := s.engines[task.Dimension]
	if !ok {
		result.Status = "failed"
		result.Error = "unknown dimension: " + task.Dimension
		result.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		s.reportResult(result)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.taskTimeout)
	defer cancel()

	slog.Info("engine start",
		"execution_id", task.ExecutionID,
		"dimension", task.Dimension,
		"url", task.URL)

	snap, err := s.pageService.FetchPage(ctx, task.URL)
	if err != nil {
		slog.Warn("page fetch failed, engine runs with error snapshot",
			"url", task.URL, "error", err)
	}

	output, err := engine.Run(ctx, task, snap)
	result.FinishedAt = time.Now().UTC().Format(time.RFC3339)

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	} else {
		result.Status = "success"
		raw, _ := json.Marshal(output)
		result.Result = string(raw)
	}

	slog.Info("engine done",
		"execution_id", task.ExecutionID,
		"dimension", task.Dimension,
		"status", result.Status)

	s.reportResult(result)
}

func (s *Scheduler) reportResult(result *TaskResult) {
	if s.onResult != nil {
		s.onResult(result)
	}
}

func (s *Scheduler) Wait() {
	s.wg.Wait()
}

func (s *Scheduler) WaitWithTimeout(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("scheduler wait timeout, force exit",
			"running", s.running.Load())
	}
}
