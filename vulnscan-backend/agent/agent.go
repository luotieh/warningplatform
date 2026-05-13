package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"time"
)

type Agent struct {
	config    Config
	client    *Client
	scheduler *Scheduler
	executors []Executor
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func New(cfg Config, executors ...Executor) *Agent {
	cfg.defaults()
	client := NewClient(cfg.MasterURL, cfg.Token)
	scheduler := NewScheduler(executors, cfg.MaxConcurrent, cfg.TaskTimeout)

	return &Agent{
		config:    cfg,
		client:    client,
		scheduler: scheduler,
		executors: executors,
	}
}

func (a *Agent) Start(ctx context.Context) error {
	ctx, a.cancel = context.WithCancel(ctx)

	for _, exec := range a.executors {
		if err := exec.Init(ctx); err != nil {
			return fmt.Errorf("init executor %s: %w", exec.Type(), err)
		}
	}

	a.scheduler.SetResultCallback(a.handleResult)

	a.wg.Add(3)
	go a.heartbeatLoop(ctx)
	go a.taskPollLoop(ctx)
	go a.commandPollLoop(ctx)

	slog.Info("agent started",
		"master", a.config.MasterURL,
		"concurrency", a.config.MaxConcurrent,
		"version", Version)

	return nil
}

func (a *Agent) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
	a.scheduler.WaitWithTimeout(30 * time.Second)
	for _, exec := range a.executors {
		exec.Close()
	}
	a.wg.Wait()
	slog.Info("agent stopped")
}

func (a *Agent) handleResult(result *TaskResult) {
	result.AgentID = a.config.Token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.client.ReportResult(ctx, result); err != nil {
		slog.Error("report result failed", "id", result.ID, "error", err)
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	defer a.wg.Done()
	ticker := time.NewTicker(a.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)

			hb := &HeartbeatReq{
				RunningTasks:  a.scheduler.RunningCount(),
				QueuedTasks:   a.scheduler.QueuedCount(),
				MaxConcurrent: a.scheduler.MaxConcurrent(),
				CPUUsage:      float64(runtime.NumGoroutine()) / float64(runtime.GOMAXPROCS(0)*100) * 100,
				MemoryUsage:   float64(memStats.Alloc) / 1024 / 1024,
				Version:       Version,
				IPAddress:     getLocalIP(),
			}

			hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := a.client.Heartbeat(hbCtx, hb); err != nil {
				slog.Warn("heartbeat failed", "error", err)
			}
			cancel()
		}
	}
}

func (a *Agent) taskPollLoop(ctx context.Context) {
	defer a.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		available := a.config.MaxConcurrent - a.scheduler.RunningCount() - a.scheduler.QueuedCount()
		if available <= 0 {
			time.Sleep(time.Second)
			continue
		}

		batch := available
		if batch > 10 {
			batch = 10
		}

		pollCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		tasks, err := a.client.PollTasks(pollCtx, batch)
		cancel()

		if err != nil {
			slog.Warn("task poll failed", "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for i := range tasks {
			a.scheduler.Submit(&tasks[i])
		}
	}
}

func (a *Agent) commandPollLoop(ctx context.Context) {
	defer a.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cmdCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		commands, err := a.client.PollCommands(cmdCtx)
		cancel()

		if err != nil {
			slog.Warn("command poll failed", "error", err)
			time.Sleep(10 * time.Second)
			continue
		}

		for _, cmd := range commands {
			slog.Info("received command", "data", string(cmd))
		}
	}
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

// Scheduler returns the scheduler for embedded mode access.
func (a *Agent) Scheduler() *Scheduler { return a.scheduler }

// Client returns the HTTP client for executor use (e.g., rule fetching).
func (a *Agent) Client() *Client { return a.client }

// NewSchedulerOnly creates a standalone scheduler without the full agent lifecycle.
// Used by embedded mode.
func NewSchedulerOnly(executors []Executor, maxConcurrent int, taskTimeout time.Duration) *Scheduler {
	return NewScheduler(executors, maxConcurrent, taskTimeout)
}

// RuleFetcher provides rule access for executors that need it.
type RuleFetcher interface {
	GetRules(ctx context.Context) (map[string]json.RawMessage, error)
}
