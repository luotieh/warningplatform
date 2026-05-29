package scanhttp

import (
	"context"
	"sync"
	"time"
)

type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
}

var globalBucket *TokenBucket
var bucketOnce sync.Once

func GetGlobalBucket() *TokenBucket {
	bucketOnce.Do(func() {
		globalBucket = NewTokenBucket(1000, 2000)
	})
	return globalBucket
}

func SetGlobalBucketRate(rps float64, burst float64) {
	b := GetGlobalBucket()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillRate = rps
	b.maxTokens = burst
	if b.tokens > burst {
		b.tokens = burst
	}
}

func NewTokenBucket(rps float64, burst float64) *TokenBucket {
	return &TokenBucket{
		tokens:     burst,
		maxTokens:  burst,
		refillRate: rps,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available or ctx is cancelled.
// Uses a single reusable timer to avoid per-iteration allocation.
func (tb *TokenBucket) Wait(ctx context.Context) error {
	if tb.tryTake() {
		return nil
	}

	wait := tb.estimateWait()
	timer := time.NewTimer(wait)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if tb.tryTake() {
				return nil
			}
			wait = tb.estimateWait()
			timer.Reset(wait)
		}
	}
}

func (tb *TokenBucket) TryTake() bool {
	return tb.tryTake()
}

func (tb *TokenBucket) tryTake() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now

	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}

	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// estimateWait computes how long to sleep before a token becomes available.
// Caps at 500ms to stay responsive, floors at 1ms to prevent zero-duration waits.
func (tb *TokenBucket) estimateWait() time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tokens := tb.tokens + elapsed*tb.refillRate
	if tokens > tb.maxTokens {
		tokens = tb.maxTokens
	}
	if tokens >= 1 || tb.refillRate <= 0 {
		return time.Millisecond
	}
	need := 1 - tokens
	sec := need / tb.refillRate
	d := time.Duration(sec * float64(time.Second))
	if d < time.Millisecond {
		return time.Millisecond
	}
	if d > 500*time.Millisecond {
		return 500 * time.Millisecond
	}
	return d
}

func (tb *TokenBucket) Stats() (tokens float64, rps float64, burst float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.tokens, tb.refillRate, tb.maxTokens
}
