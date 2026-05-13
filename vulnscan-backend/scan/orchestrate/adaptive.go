package orchestrate

import (
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

type AdaptiveController struct {
	mu sync.Mutex

	minConcurrency int
	maxConcurrency int
	current        atomic.Int32

	windowSize    int
	latencies     []float64
	successCount  atomic.Int64
	failureCount  atomic.Int64
	totalRequests atomic.Int64

	lastAdjust     time.Time
	adjustInterval time.Duration

	state         circuitState
	failStreak    int
	openUntil     time.Time
	halfOpenLimit int
	halfOpenCount int
}

type circuitState int

const (
	stateClosed circuitState = iota
	stateOpen
	stateHalfOpen
)

func NewAdaptiveController(minConc, maxConc int) *AdaptiveController {
	ac := &AdaptiveController{
		minConcurrency: minConc,
		maxConcurrency: maxConc,
		windowSize:     100,
		latencies:      make([]float64, 0, 100),
		adjustInterval: 5 * time.Second,
		lastAdjust:     time.Now(),
		state:          stateClosed,
		halfOpenLimit:  3,
	}
	ac.current.Store(int32((minConc + maxConc) / 2))
	return ac
}

func (ac *AdaptiveController) CurrentConcurrency() int {
	return int(ac.current.Load())
}

func (ac *AdaptiveController) RecordSuccess(latencyMs float64) {
	ac.successCount.Add(1)
	ac.totalRequests.Add(1)

	ac.mu.Lock()
	ac.failStreak = 0
	if ac.state == stateHalfOpen {
		ac.halfOpenCount++
		if ac.halfOpenCount >= ac.halfOpenLimit {
			ac.state = stateClosed
			slog.Info("[Adaptive] 熔断恢复 → Closed")
		}
	}
	ac.latencies = append(ac.latencies, latencyMs)
	if len(ac.latencies) > ac.windowSize {
		ac.latencies = ac.latencies[len(ac.latencies)-ac.windowSize:]
	}
	ac.mu.Unlock()

	ac.maybeAdjust()
}

func (ac *AdaptiveController) RecordFailure(latencyMs float64) {
	ac.failureCount.Add(1)
	ac.totalRequests.Add(1)

	ac.mu.Lock()
	ac.failStreak++
	if ac.failStreak >= 10 && ac.state == stateClosed {
		ac.state = stateOpen
		ac.openUntil = time.Now().Add(30 * time.Second)
		newConc := int32(ac.minConcurrency)
		ac.current.Store(newConc)
		slog.Warn("[Adaptive] 连续失败触发熔断 → Open", "failStreak", ac.failStreak, "concurrency", newConc)
	}
	ac.mu.Unlock()

	ac.maybeAdjust()
}

func (ac *AdaptiveController) IsOpen() bool {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if ac.state == stateOpen {
		if time.Now().After(ac.openUntil) {
			ac.state = stateHalfOpen
			ac.halfOpenCount = 0
			slog.Info("[Adaptive] 熔断半开 → HalfOpen")
			return false
		}
		return true
	}
	return false
}

func (ac *AdaptiveController) maybeAdjust() {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if time.Since(ac.lastAdjust) < ac.adjustInterval {
		return
	}
	ac.lastAdjust = time.Now()

	if len(ac.latencies) < 10 {
		return
	}

	if ac.state != stateClosed {
		return
	}

	avgLatency := ac.avgLatency()
	p95 := ac.percentile(95)
	successRate := ac.currentSuccessRate()
	current := int(ac.current.Load())

	var newConc int

	switch {
	case successRate > 0.98 && avgLatency < 200:
		newConc = current + max(1, current/5)
	case successRate > 0.95 && avgLatency < 500:
		newConc = current + max(1, current/10)
	case successRate < 0.80 || p95 > 5000:
		newConc = current - max(1, current/3)
	case successRate < 0.90 || p95 > 2000:
		newConc = current - max(1, current/5)
	default:
		return
	}

	newConc = max(ac.minConcurrency, min(ac.maxConcurrency, newConc))
	if newConc != current {
		ac.current.Store(int32(newConc))
		slog.Info("[Adaptive] 并发调整",
			"old", current, "new", newConc,
			"avgLatency", int(avgLatency), "p95", int(p95),
			"successRate", int(successRate*100),
		)
	}
}

func (ac *AdaptiveController) avgLatency() float64 {
	if len(ac.latencies) == 0 {
		return 0
	}
	sum := 0.0
	for _, l := range ac.latencies {
		sum += l
	}
	return sum / float64(len(ac.latencies))
}

func (ac *AdaptiveController) percentile(pct float64) float64 {
	n := len(ac.latencies)
	if n == 0 {
		return 0
	}

	sorted := make([]float64, n)
	copy(sorted, ac.latencies)
	for i := 1; i < n; i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	idx := int(math.Ceil(pct/100*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

func (ac *AdaptiveController) currentSuccessRate() float64 {
	total := ac.totalRequests.Load()
	if total == 0 {
		return 1.0
	}
	succ := ac.successCount.Load()
	return float64(succ) / float64(total)
}

func (ac *AdaptiveController) Stats() map[string]interface{} {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	return map[string]interface{}{
		"current_concurrency": int(ac.current.Load()),
		"min_concurrency":     ac.minConcurrency,
		"max_concurrency":     ac.maxConcurrency,
		"total_requests":      ac.totalRequests.Load(),
		"success_count":       ac.successCount.Load(),
		"failure_count":       ac.failureCount.Load(),
		"avg_latency_ms":      int(ac.avgLatency()),
		"p95_latency_ms":      int(ac.percentile(95)),
		"circuit_state":       ac.stateString(),
	}
}

func (ac *AdaptiveController) stateString() string {
	switch ac.state {
	case stateClosed:
		return "closed"
	case stateOpen:
		return "open"
	case stateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}
