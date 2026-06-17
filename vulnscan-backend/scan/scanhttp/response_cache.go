package scanhttp

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ResponseCache provides an in-memory HTTP response cache keyed by
// Method+URL+selected headers. Only GET/HEAD responses with 2xx status
// are cached. This avoids redundant network round-trips when multiple
// scan modules fetch the same URL (e.g. fingerprint, crawler, tech detect).
type ResponseCache struct {
	mu       sync.RWMutex
	items    map[string]*list.Element
	order    *list.List
	maxSize  int
	ttl      time.Duration
	hits     atomic.Int64
	misses   atomic.Int64
	disabled bool
}

type cachedResponse struct {
	key        string
	statusCode int
	headers    http.Header
	body       []byte
	cachedAt   time.Time
}

var (
	globalResponseCache     *ResponseCache
	globalResponseCacheOnce sync.Once
)

// GetGlobalResponseCache returns the singleton response cache.
func GetGlobalResponseCache() *ResponseCache {
	globalResponseCacheOnce.Do(func() {
		globalResponseCache = NewResponseCache(8192, 5*time.Minute)
	})
	return globalResponseCache
}

// SetGlobalResponseCacheDisabled toggles the cache on/off at runtime.
func SetGlobalResponseCacheDisabled(disabled bool) {
	GetGlobalResponseCache().disabled = disabled
}

func NewResponseCache(maxSize int, ttl time.Duration) *ResponseCache {
	if maxSize <= 0 {
		maxSize = 4096
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &ResponseCache{
		items:   make(map[string]*list.Element, maxSize),
		order:   list.New(),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func responseCacheKey(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(req.Method))
	h.Write([]byte("|"))
	h.Write([]byte(strings.ToLower(req.URL.String())))
	return hex.EncodeToString(h.Sum(nil))
}

func isCacheableMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func isCacheableStatus(code int) bool {
	return code >= 200 && code < 300
}

// Get looks up a cached response. Returns nil if not found or expired.
func (c *ResponseCache) Get(req *http.Request) *cachedResponse {
	if c.disabled || !isCacheableMethod(req.Method) {
		c.misses.Add(1)
		return nil
	}
	key := responseCacheKey(req)
	c.mu.RLock()
	elem, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		c.misses.Add(1)
		return nil
	}
	item := elem.Value.(*cachedResponse)
	if time.Since(item.cachedAt) > c.ttl {
		c.mu.Lock()
		c.order.Remove(elem)
		delete(c.items, key)
		c.mu.Unlock()
		c.misses.Add(1)
		return nil
	}
	c.hits.Add(1)
	return item
}

// Put stores a response in the cache.
func (c *ResponseCache) Put(req *http.Request, statusCode int, headers http.Header, body []byte) {
	if c.disabled || !isCacheableMethod(req.Method) || !isCacheableStatus(statusCode) {
		return
	}
	if len(body) > 2*1024*1024 {
		return
	}
	key := responseCacheKey(req)

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.items[key]; exists {
		item := elem.Value.(*cachedResponse)
		item.statusCode = statusCode
		item.headers = headers.Clone()
		item.body = body
		item.cachedAt = time.Now()
		c.order.MoveToBack(elem)
		return
	}

	for c.order.Len() >= c.maxSize {
		front := c.order.Front()
		if front == nil {
			break
		}
		old := c.order.Remove(front).(*cachedResponse)
		delete(c.items, old.key)
	}

	entry := &cachedResponse{
		key:        key,
		statusCode: statusCode,
		headers:    headers.Clone(),
		body:       body,
		cachedAt:   time.Now(),
	}
	elem := c.order.PushBack(entry)
	c.items[key] = elem
}

// Stats returns cache hit/miss counts.
func (c *ResponseCache) Stats() (hits, misses int64) {
	return c.hits.Load(), c.misses.Load()
}

// HitRate returns the fraction of lookups that hit the cache.
func (c *ResponseCache) HitRate() float64 {
	h := c.hits.Load()
	m := c.misses.Load()
	total := h + m
	if total == 0 {
		return 0
	}
	return float64(h) / float64(total)
}

// Size returns the number of entries in the cache.
func (c *ResponseCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.order.Len()
}

func init() {
	slog.Debug("[ResponseCache] HTTP 响应缓存就绪")
}
