package monitoragent

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"time"
)

const AgentVersion = "1.0.0"

type AgentConfig struct {
	MasterURL     string
	AgentToken    string
	MaxConcurrent int
	TaskTimeout   time.Duration
	HeartbeatSec  int
	Region        string
	Label         string
}

type Agent struct {
	config      AgentConfig
	client      *MasterClient
	scheduler   *Scheduler
	pageService *PageService
	rules       *MemoryRuleStore
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

func NewAgent(cfg AgentConfig) *Agent {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 5
	}
	if cfg.TaskTimeout <= 0 {
		cfg.TaskTimeout = 5 * time.Minute
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 10
	}

	client := NewMasterClient(cfg.MasterURL, cfg.AgentToken)
	ps := NewPageService()
	sched := NewScheduler(ps, cfg.MaxConcurrent, cfg.TaskTimeout)
	rules := &MemoryRuleStore{data: make(map[string][]byte)}

	agent := &Agent{
		config:      cfg,
		client:      client,
		scheduler:   sched,
		pageService: ps,
		rules:       rules,
	}

	sched.SetResultCallback(agent.handleResult)

	sched.RegisterEngine(&AvailabilityEngine{Rules: rules})
	sched.RegisterEngine(&TamperEngine{Rules: rules})
	sched.RegisterEngine(&BlacklinkEngine{Rules: rules})
	sched.RegisterEngine(&SensitiveWordEngine{Rules: rules})
	sched.RegisterEngine(&SensitiveFileEngine{Rules: rules})
	sched.RegisterEngine(&DomainHijackEngine{Rules: rules})

	return agent
}

func (a *Agent) Start(ctx context.Context) {
	ctx, a.cancel = context.WithCancel(ctx)

	slog.Info("monitor agent starting",
		"master", a.config.MasterURL,
		"concurrency", a.config.MaxConcurrent,
		"version", AgentVersion)

	a.syncRules(ctx)

	a.wg.Add(3)
	go a.heartbeatLoop(ctx)
	go a.taskPollLoop(ctx)
	go a.commandPollLoop(ctx)

	slog.Info("monitor agent started")
}

func (a *Agent) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
	a.scheduler.WaitWithTimeout(30 * time.Second)
	a.pageService.Close()
	a.wg.Wait()
	slog.Info("monitor agent stopped")
}

func (a *Agent) handleResult(result *TaskResult) {
	result.AgentID = a.config.AgentToken
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.client.ReportResult(ctx, result); err != nil {
		slog.Error("failed to report result",
			"execution_id", result.ExecutionID,
			"error", err)
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	defer a.wg.Done()
	ticker := time.NewTicker(time.Duration(a.config.HeartbeatSec) * time.Second)
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
				MaxQueue:      100,
				CPUUsage:      0,
				MemoryUsage:   float64(memStats.Alloc) / 1024 / 1024,
				Version:       AgentVersion,
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

		if len(tasks) > 0 {
			slog.Info("polled tasks", "count", len(tasks))
			a.scheduler.SubmitBatch(tasks)
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

func (a *Agent) syncRules(ctx context.Context) {
	ruleCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rules, err := a.client.GetRules(ruleCtx)
	if err != nil {
		slog.Warn("initial rule sync failed", "error", err)
		return
	}

	a.rules.mu.Lock()
	for k, v := range rules {
		a.rules.data[k] = []byte(v)
	}
	a.rules.mu.Unlock()

	slog.Info("rules synced", "count", len(rules))
}

type MemoryRuleStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func (m *MemoryRuleStore) GetModuleRules(key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.data[key], nil
}

func (m *MemoryRuleStore) GetAllRules() (map[string][]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make(map[string][]byte, len(m.data))
	for k, v := range m.data {
		cp[k] = v
	}
	return cp, nil
}
