package scanrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"vulnscan-backend/scan/core"
)

type cachedResult struct {
	findings []*core.Finding
	cachedAt time.Time
}

type ResultCache struct {
	mu      sync.RWMutex
	items   map[string]*cachedResult
	order   []string
	maxSize int
	ttl     time.Duration
	hits    atomic.Int64
	misses  atomic.Int64
}

func NewResultCache(maxSize int, ttl time.Duration) *ResultCache {
	return &ResultCache{
		items:   make(map[string]*cachedResult, maxSize),
		order:   make([]string, 0, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func (c *ResultCache) Key(target, moduleID string, config map[string]interface{}) string {
	h := sha256.New()
	h.Write([]byte(target))
	h.Write([]byte("|"))
	h.Write([]byte(moduleID))
	if len(config) > 0 {
		h.Write([]byte("|"))
		keys := make([]string, 0, len(config))
		for k := range config {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k))
			h.Write([]byte("="))
			v, _ := json.Marshal(config[k])
			h.Write(v)
			h.Write([]byte(";"))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *ResultCache) Get(key string) ([]*core.Finding, bool) {
	c.mu.RLock()
	item, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil, false
	}

	if time.Since(item.cachedAt) > c.ttl {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}

	c.hits.Add(1)
	return item.findings, true
}

func (c *ResultCache) Set(key string, findings []*core.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.items[key]; exists {
		c.items[key] = &cachedResult{findings: findings, cachedAt: time.Now()}
		return
	}

	if len(c.items) >= c.maxSize {
		c.evict()
	}

	c.items[key] = &cachedResult{findings: findings, cachedAt: time.Now()}
	c.order = append(c.order, key)
}

func (c *ResultCache) evict() {
	for len(c.order) > 0 && len(c.items) >= c.maxSize {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.items, oldest)
	}
}

func (c *ResultCache) HitRate() float64 {
	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total)
}

func (c *ResultCache) Stats() (hits, misses int64) {
	return c.hits.Load(), c.misses.Load()
}
