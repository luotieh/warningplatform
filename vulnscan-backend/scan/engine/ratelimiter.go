package engine

import (
	"context"
	"sync"
	"time"
)

// TokenBucket provides a global token-bucket rate limiter shared across all scan modules.
// Different from RateLimiter (channel-based per-target), this is a single global bucket.
type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
}

var globalBucket *TokenBucket
var bucketOnce sync.Once

// GetGlobalBucket returns the singleton token bucket.
// Default: 1000 requests/second, burst up to 2000.
func GetGlobalBucket() *TokenBucket {
	bucketOnce.Do(func() {
		globalBucket = NewTokenBucket(1000, 2000)
	})
	return globalBucket
}

// SetGlobalBucketRate reconfigures the global bucket.
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
func (tb *TokenBucket) Wait(ctx context.Context) error {
	for {
		if tb.tryTake() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

// TryTake attempts to take a token without blocking.
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

// Stats returns current bucket stats.
func (tb *TokenBucket) Stats() (tokens float64, rps float64, burst float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.tokens, tb.refillRate, tb.maxTokens
}
