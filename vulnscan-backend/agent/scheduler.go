package agent

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Scheduler struct {
	executors   map[string]Executor
	sem         chan struct{}
	running     atomic.Int32
	queued      atomic.Int32
	maxConc     int
	taskTimeout time.Duration
	wg          sync.WaitGroup
	onResult    func(*TaskResult)
}

func NewScheduler(executors []Executor, maxConcurrent int, taskTimeout time.Duration) *Scheduler {
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}
	if taskTimeout <= 0 {
		taskTimeout = 10 * time.Minute
	}

	execMap := make(map[string]Executor, len(executors))
	for _, e := range executors {
		execMap[e.Type()] = e
	}

	return &Scheduler{
		executors:   execMap,
		sem:         make(chan struct{}, maxConcurrent),
		maxConc:     maxConcurrent,
		taskTimeout: taskTimeout,
	}
}

func (s *Scheduler) SetResultCallback(fn func(*TaskResult)) {
	s.onResult = fn
}

func (s *Scheduler) RunningCount() int  { return int(s.running.Load()) }
func (s *Scheduler) QueuedCount() int   { return int(s.queued.Load()) }
func (s *Scheduler) MaxConcurrent() int { return s.maxConc }

func (s *Scheduler) Submit(task *TaskEnvelope) {
	s.queued.Add(1)
	s.wg.Add(1)
	go s.execute(task)
}

func (s *Scheduler) execute(task *TaskEnvelope) {
	defer s.wg.Done()

	s.sem <- struct{}{}
	s.queued.Add(-1)
	s.running.Add(1)
	defer func() {
		<-s.sem
		s.running.Add(-1)
	}()

	executor, ok := s.executors[task.Type]
	if !ok {
		result := &TaskResult{
			ID:         task.ID,
			Type:       task.Type,
			Status:     "failed",
			Error:      "unknown task type: " + task.Type,
			StartedAt:  time.Now().UTC().Format(time.RFC3339),
			FinishedAt: time.Now().UTC().Format(time.RFC3339),
		}
		s.reportResult(result)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.taskTimeout)
	defer cancel()

	slog.Info("task start", "id", task.ID, "type", task.Type)

	result := executor.Execute(ctx, task.Payload)
	result.ID = task.ID
	result.Type = task.Type

	slog.Info("task done", "id", task.ID, "type", task.Type, "status", result.Status)
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
		slog.Warn("scheduler wait timeout", "running", s.running.Load())
	}
}
