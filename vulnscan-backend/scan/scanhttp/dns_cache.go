package scanhttp

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

// DNSCache provides an in-memory DNS resolution cache to avoid redundant lookups
// during scanning. Results are cached per hostname with a configurable TTL.
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsEntry
	ttl     time.Duration
	hits    int64
	misses  int64
}

type dnsEntry struct {
	addrs    []string
	cachedAt time.Time
	err      error
}

var (
	globalDNSCache     *DNSCache
	globalDNSCacheOnce sync.Once
)

func GetGlobalDNSCache() *DNSCache {
	globalDNSCacheOnce.Do(func() {
		globalDNSCache = NewDNSCache(5 * time.Minute)
	})
	return globalDNSCache
}

func NewDNSCache(ttl time.Duration) *DNSCache {
	dc := &DNSCache{
		entries: make(map[string]*dnsEntry),
		ttl:     ttl,
	}
	go dc.cleanupLoop()
	return dc
}

// LookupHost resolves hostname IPs with caching.
func (dc *DNSCache) LookupHost(ctx context.Context, host string) ([]string, error) {
	dc.mu.RLock()
	entry, ok := dc.entries[host]
	dc.mu.RUnlock()

	if ok && time.Since(entry.cachedAt) < dc.ttl {
		dc.mu.Lock()
		dc.hits++
		dc.mu.Unlock()
		return entry.addrs, entry.err
	}

	addrs, err := net.DefaultResolver.LookupHost(ctx, host)

	dc.mu.Lock()
	dc.misses++
	dc.entries[host] = &dnsEntry{
		addrs:    addrs,
		cachedAt: time.Now(),
		err:      err,
	}
	dc.mu.Unlock()

	return addrs, err
}

// CachedDialContext returns a DialContext function that uses cached DNS resolution.
func (dc *DNSCache) CachedDialContext(baseDialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return baseDialer.DialContext(ctx, network, addr)
		}

		ip := net.ParseIP(host)
		if ip != nil {
			return baseDialer.DialContext(ctx, network, addr)
		}

		addrs, err := dc.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return baseDialer.DialContext(ctx, network, addr)
		}

		var lastErr error
		for _, resolved := range addrs {
			conn, err := baseDialer.DialContext(ctx, network, net.JoinHostPort(resolved, port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func (dc *DNSCache) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		dc.mu.Lock()
		now := time.Now()
		for host, entry := range dc.entries {
			if now.Sub(entry.cachedAt) > dc.ttl*2 {
				delete(dc.entries, host)
			}
		}
		dc.mu.Unlock()
	}
}

func (dc *DNSCache) Stats() (hits, misses int64, size int) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	return dc.hits, dc.misses, len(dc.entries)
}

func (dc *DNSCache) HitRate() float64 {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	total := dc.hits + dc.misses
	if total == 0 {
		return 0
	}
	return float64(dc.hits) / float64(total)
}

func (dc *DNSCache) LogStats() {
	hits, misses, size := dc.Stats()
	slog.Info("[DNSCache] 统计",
		"hits", hits, "misses", misses, "size", size,
		"hit_rate", dc.HitRate())
}
