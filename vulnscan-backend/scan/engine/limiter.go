package engine

import (
	"context"
	"sync"
	"time"
)

type RateLimiter struct {
	globalRate int
	targetRate int
	globalCh   chan struct{}
	targetChs  map[string]chan struct{}
	mu         sync.Mutex
}

func NewRateLimiter(globalRate, targetRate int) *RateLimiter {
	rl := &RateLimiter{
		globalRate: globalRate,
		targetRate: targetRate,
		globalCh:   make(chan struct{}, globalRate),
		targetChs:  make(map[string]chan struct{}),
	}

	go rl.refillLoop()
	return rl
}

func (rl *RateLimiter) Acquire(ctx context.Context, target string) error {
	select {
	case rl.globalCh <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}

	targetCh := rl.getTargetCh(target)
	select {
	case targetCh <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rl *RateLimiter) getTargetCh(target string) chan struct{} {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	ch, ok := rl.targetChs[target]
	if !ok {
		ch = make(chan struct{}, rl.targetRate)
		rl.targetChs[target] = ch
	}
	return ch
}

func (rl *RateLimiter) refillLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		for len(rl.globalCh) > 0 {
			<-rl.globalCh
		}

		rl.mu.Lock()
		for _, ch := range rl.targetChs {
			for len(ch) > 0 {
				<-ch
			}
		}
		rl.mu.Unlock()
	}
}
