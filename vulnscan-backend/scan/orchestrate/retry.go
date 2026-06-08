package orchestrate

import (
	"code.yt-security.com/public/scanengine/core"

	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

var DefaultRetryConfig = RetryConfig{
	MaxRetries:     2,
	InitialBackoff: 500 * time.Millisecond,
	MaxBackoff:     5 * time.Second,
}

func RunWithRetry(ctx context.Context, mod core.ScanModule, targets []*core.Target, config map[string]interface{}, rc RetryConfig) (*core.ModuleResult, error) {
	var lastErr error
	backoff := rc.InitialBackoff

	for attempt := 0; attempt <= rc.MaxRetries; attempt++ {
		if attempt > 0 {
			slog.Warn("[Retry] 模块重试",
				"module", mod.ID(),
				"attempt", attempt,
				"backoff", backoff,
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > rc.MaxBackoff {
				backoff = rc.MaxBackoff
			}
		}

		result, err := mod.Run(ctx, targets, config)
		if err == nil {
			return result, nil
		}

		lastErr = err
		slog.Warn("[Retry] 模块执行失败",
			"module", mod.ID(),
			"attempt", attempt,
			"error", err,
		)
	}

	return nil, fmt.Errorf("模块 %s 重试 %d 次后仍失败: %w", mod.ID(), rc.MaxRetries, lastErr)
}

type CircuitBreaker struct {
	mu              sync.RWMutex
	modules         map[string]*moduleCircuit
	failThreshold   int
	resetTimeout    time.Duration
	halfOpenMaxReqs int
}

type moduleCircuit struct {
	state        circuitState
	failCount    atomic.Int32
	successCount atomic.Int32
	lastFailure  time.Time
	openUntil    time.Time
	halfOpenReqs int
}

func NewCircuitBreaker(failThreshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		modules:         make(map[string]*moduleCircuit),
		failThreshold:   failThreshold,
		resetTimeout:    resetTimeout,
		halfOpenMaxReqs: 2,
	}
}

func (cb *CircuitBreaker) getCircuit(moduleID string) *moduleCircuit {
	cb.mu.RLock()
	mc, ok := cb.modules[moduleID]
	cb.mu.RUnlock()
	if ok {
		return mc
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()
	if mc, ok = cb.modules[moduleID]; ok {
		return mc
	}
	mc = &moduleCircuit{state: stateClosed}
	cb.modules[moduleID] = mc
	return mc
}

func (cb *CircuitBreaker) CanExecute(moduleID string) bool {
	mc := cb.getCircuit(moduleID)

	switch mc.state {
	case stateClosed:
		return true
	case stateOpen:
		if time.Now().After(mc.openUntil) {
			mc.state = stateHalfOpen
			mc.halfOpenReqs = 0
			slog.Info("[CircuitBreaker] HalfOpen", "module", moduleID)
			return true
		}
		return false
	case stateHalfOpen:
		return mc.halfOpenReqs < cb.halfOpenMaxReqs
	}
	return true
}

func (cb *CircuitBreaker) RecordSuccess(moduleID string) {
	mc := cb.getCircuit(moduleID)
	mc.successCount.Add(1)
	mc.failCount.Store(0)

	if mc.state == stateHalfOpen {
		mc.halfOpenReqs++
		if mc.halfOpenReqs >= cb.halfOpenMaxReqs {
			mc.state = stateClosed
			slog.Info("[CircuitBreaker] Closed (recovered)", "module", moduleID)
		}
	}
}

func (cb *CircuitBreaker) RecordFailure(moduleID string) {
	mc := cb.getCircuit(moduleID)
	mc.failCount.Add(1)
	mc.lastFailure = time.Now()

	if mc.state == stateHalfOpen {
		mc.state = stateOpen
		mc.openUntil = time.Now().Add(cb.resetTimeout * 2)
		slog.Warn("[CircuitBreaker] Open (half-open failed)", "module", moduleID)
		return
	}

	if int(mc.failCount.Load()) >= cb.failThreshold && mc.state == stateClosed {
		mc.state = stateOpen
		mc.openUntil = time.Now().Add(cb.resetTimeout)
		slog.Warn("[CircuitBreaker] Open", "module", moduleID,
			"failures", mc.failCount.Load(), "resetAt", mc.openUntil.Format(time.RFC3339))
	}
}

func (cb *CircuitBreaker) Stats() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	result := make(map[string]interface{})
	for id, mc := range cb.modules {
		result[id] = map[string]interface{}{
			"state":     stateStr(mc.state),
			"failures":  mc.failCount.Load(),
			"successes": mc.successCount.Load(),
		}
	}
	return result
}

func stateStr(s circuitState) string {
	switch s {
	case stateClosed:
		return "closed"
	case stateOpen:
		return "open"
	case stateHalfOpen:
		return "half_open"
	}
	return "unknown"
}
