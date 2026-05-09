package engine

import (
	"context"
	"sync"
	"time"
)

type TokenBucket struct {
	mu         sync.Mutex
	cond       *sync.Cond
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
	b.cond.Broadcast()
}

func NewTokenBucket(rps float64, burst float64) *TokenBucket {
	tb := &TokenBucket{
		tokens:     burst,
		maxTokens:  burst,
		refillRate: rps,
		lastRefill: time.Now(),
	}
	tb.cond = sync.NewCond(&tb.mu)
	return tb
}

func (tb *TokenBucket) Wait(ctx context.Context) error {
	for {
		if tb.tryTake() {
			return nil
		}

		tb.mu.Lock()
		waitDone := make(chan struct{})
		go func() {
			tb.cond.Wait()
			close(waitDone)
		}()

		select {
		case <-ctx.Done():
			tb.cond.Broadcast()
			tb.mu.Unlock()
			return ctx.Err()
		case <-waitDone:
			tb.mu.Unlock()
		case <-time.After(50 * time.Millisecond):
			tb.mu.Unlock()
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
		tb.cond.Broadcast()
		return true
	}
	return false
}

func (tb *TokenBucket) Stats() (tokens float64, rps float64, burst float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.tokens, tb.refillRate, tb.maxTokens
}
