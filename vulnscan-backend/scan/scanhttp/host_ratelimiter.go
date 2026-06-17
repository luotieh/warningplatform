package scanhttp

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	defaultHostRPS      = 50.0
	defaultHostBurst    = 80.0
	hostBucketTTL       = 10 * time.Minute
	maxHostBuckets      = 4096
	hostCleanupInterval = 2 * time.Minute
)

// HostRateLimiter maintains per-hostname token buckets to prevent
// overwhelming individual targets with too many concurrent requests.
type HostRateLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*hostEntry
	rps     float64
	burst   float64
	stopped chan struct{}
}

type hostEntry struct {
	bucket   *TokenBucket
	lastUsed time.Time
}

var (
	globalHostRateLimiter     *HostRateLimiter
	globalHostRateLimiterOnce sync.Once
)

// GetGlobalHostRateLimiter returns the singleton per-host rate limiter.
func GetGlobalHostRateLimiter() *HostRateLimiter {
	globalHostRateLimiterOnce.Do(func() {
		globalHostRateLimiter = NewHostRateLimiter(defaultHostRPS, defaultHostBurst)
	})
	return globalHostRateLimiter
}

// SetGlobalHostRateLimit updates the per-host rate limit parameters at runtime.
func SetGlobalHostRateLimit(rps, burst float64) {
	rl := GetGlobalHostRateLimiter()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.rps = rps
	rl.burst = burst
	slog.Info("[HostRateLimiter] 已更新全局主机限速", "rps", rps, "burst", burst)
}

func NewHostRateLimiter(rps, burst float64) *HostRateLimiter {
	if rps <= 0 {
		rps = defaultHostRPS
	}
	if burst <= 0 {
		burst = defaultHostBurst
	}
	rl := &HostRateLimiter{
		buckets: make(map[string]*hostEntry, 256),
		rps:     rps,
		burst:   burst,
		stopped: make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Wait blocks until the per-host token bucket allows a request.
func (rl *HostRateLimiter) Wait(ctx context.Context, hostname string) error {
	if hostname == "" {
		return nil
	}
	bucket := rl.getOrCreateBucket(hostname)
	return bucket.Wait(ctx)
}

func (rl *HostRateLimiter) getOrCreateBucket(hostname string) *TokenBucket {
	rl.mu.RLock()
	entry, ok := rl.buckets[hostname]
	rl.mu.RUnlock()
	if ok {
		entry.lastUsed = time.Now()
		return entry.bucket
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if entry, ok = rl.buckets[hostname]; ok {
		entry.lastUsed = time.Now()
		return entry.bucket
	}

	if len(rl.buckets) >= maxHostBuckets {
		rl.evictStaleLocked()
	}

	bucket := NewTokenBucket(rl.rps, rl.burst)
	rl.buckets[hostname] = &hostEntry{
		bucket:   bucket,
		lastUsed: time.Now(),
	}
	return bucket
}

func (rl *HostRateLimiter) evictStaleLocked() {
	cutoff := time.Now().Add(-hostBucketTTL)
	for k, e := range rl.buckets {
		if e.lastUsed.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
	if len(rl.buckets) >= maxHostBuckets {
		oldest := ""
		var oldestTime time.Time
		for k, e := range rl.buckets {
			if oldest == "" || e.lastUsed.Before(oldestTime) {
				oldest = k
				oldestTime = e.lastUsed
			}
		}
		if oldest != "" {
			delete(rl.buckets, oldest)
		}
	}
}

func (rl *HostRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(hostCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-hostBucketTTL)
			evicted := 0
			for k, e := range rl.buckets {
				if e.lastUsed.Before(cutoff) {
					delete(rl.buckets, k)
					evicted++
				}
			}
			rl.mu.Unlock()
			if evicted > 0 {
				slog.Debug("[HostRateLimiter] 清理过期主机桶", "evicted", evicted)
			}
		case <-rl.stopped:
			return
		}
	}
}

// ActiveHosts returns the number of tracked hostnames.
func (rl *HostRateLimiter) ActiveHosts() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return len(rl.buckets)
}

// Stop halts the background cleanup goroutine.
func (rl *HostRateLimiter) Stop() {
	select {
	case <-rl.stopped:
	default:
		close(rl.stopped)
	}
}
