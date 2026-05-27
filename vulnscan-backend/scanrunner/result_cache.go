package scanrunner

import (
	"container/list"
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
	key      string
	findings []*core.Finding
	cachedAt time.Time
}

type ResultCache struct {
	mu      sync.RWMutex
	items   map[string]*list.Element
	order   *list.List
	maxSize int
	ttl     time.Duration
	hits    atomic.Int64
	misses  atomic.Int64
}

func NewResultCache(maxSize int, ttl time.Duration) *ResultCache {
	return &ResultCache{
		items:   make(map[string]*list.Element, maxSize),
		order:   list.New(),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

var cacheKeyExcludedPrefixes = []string{
	"scan_task_id", "scan_parent_task_id",
	"detected_products", "detected_wafs",
	"target_count", "_shard_index", "_total_shards",
	"worker_id", "worker_target_sharding",
}

func isCacheKeyExcluded(key string) bool {
	for _, prefix := range cacheKeyExcludedPrefixes {
		if key == prefix {
			return true
		}
	}
	return false
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
			if !isCacheKeyExcluded(k) {
				keys = append(keys, k)
			}
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
	elem, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil, false
	}

	item := elem.Value.(*cachedResult)
	if time.Since(item.cachedAt) > c.ttl {
		c.mu.Lock()
		c.order.Remove(elem)
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

	if elem, exists := c.items[key]; exists {
		item := elem.Value.(*cachedResult)
		item.findings = findings
		item.cachedAt = time.Now()
		c.order.MoveToBack(elem)
		return
	}

	for c.order.Len() >= c.maxSize {
		c.evict()
	}

	entry := &cachedResult{key: key, findings: findings, cachedAt: time.Now()}
	elem := c.order.PushBack(entry)
	c.items[key] = elem
}

func (c *ResultCache) evict() {
	front := c.order.Front()
	if front == nil {
		return
	}
	item := c.order.Remove(front).(*cachedResult)
	delete(c.items, item.key)
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
