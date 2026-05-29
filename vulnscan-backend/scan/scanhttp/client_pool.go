package scanhttp

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	globalClientPool     *ClientPool
	globalClientPoolOnce sync.Once
)

const (
	defaultPoolMaxClients = 256
	defaultPoolClientTTL  = 10 * time.Minute
)

type poolEntry struct {
	client   *ScanHTTPClient
	lastUsed time.Time
}

type ClientPool struct {
	defaultClient *ScanHTTPClient
	clients       map[string]*poolEntry
	mu            sync.RWMutex
	config        ClientConfig
	maxClients    int
	clientTTL     time.Duration
}

func GetGlobalClientPool() *ClientPool {
	globalClientPoolOnce.Do(func() {
		globalClientPool = &ClientPool{
			defaultClient: NewScanHTTPClient(),
			clients:       make(map[string]*poolEntry),
			config:        defaultClientConfig,
			maxClients:    defaultPoolMaxClients,
			clientTTL:     defaultPoolClientTTL,
		}
	})
	return globalClientPool
}

func (p *ClientPool) GetDefault() *ScanHTTPClient {
	return p.defaultClient
}

func (p *ClientPool) GetOrCreate(key string, opts ...ClientOption) *ScanHTTPClient {
	if key == "" {
		return p.defaultClient
	}

	p.mu.RLock()
	entry, ok := p.clients[key]
	p.mu.RUnlock()
	if ok {
		p.mu.Lock()
		entry.lastUsed = time.Now()
		p.mu.Unlock()
		return entry.client
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if entry, ok = p.clients[key]; ok {
		entry.lastUsed = time.Now()
		return entry.client
	}

	if len(p.clients) >= p.maxClients {
		p.evictStaleLocked()
	}

	cfg := p.config
	for _, opt := range opts {
		opt(&cfg)
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	var redirectFn func(req *http.Request, via []*http.Request) error
	switch cfg.RedirectPolicy {
	case RedirectNoFollow:
		redirectFn = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	default:
		maxRedir := cfg.MaxRedirects
		redirectFn = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedir {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}

	client := &ScanHTTPClient{
		client: &http.Client{
			Timeout:       cfg.Timeout,
			Transport:     transport,
			CheckRedirect: redirectFn,
		},
		config:      cfg,
		retryAfter:  make(map[string]time.Time),
		authHeaders: cfg.AuthHeaders,
		authCookies: cfg.AuthCookies,
		rateLimiter: GetGlobalBucket(),
	}

	p.clients[key] = &poolEntry{
		client:   client,
		lastUsed: time.Now(),
	}
	return client
}

// evictStaleLocked removes entries older than clientTTL, or the oldest 25% if still over capacity.
// Caller must hold p.mu write lock.
func (p *ClientPool) evictStaleLocked() {
	cutoff := time.Now().Add(-p.clientTTL)
	evicted := 0

	for k, entry := range p.clients {
		if entry.lastUsed.Before(cutoff) {
			p.closeClientLocked(entry)
			delete(p.clients, k)
			evicted++
		}
	}

	if len(p.clients) >= p.maxClients {
		toEvict := len(p.clients) / 4
		if toEvict == 0 {
			toEvict = 1
		}
		type kv struct {
			key      string
			lastUsed time.Time
		}
		entries := make([]kv, 0, len(p.clients))
		for k, entry := range p.clients {
			entries = append(entries, kv{key: k, lastUsed: entry.lastUsed})
		}
		for i := 1; i < len(entries); i++ {
			for j := i; j > 0 && entries[j].lastUsed.Before(entries[j-1].lastUsed); j-- {
				entries[j], entries[j-1] = entries[j-1], entries[j]
			}
		}
		for i := 0; i < toEvict && i < len(entries); i++ {
			if entry, ok := p.clients[entries[i].key]; ok {
				p.closeClientLocked(entry)
			}
			delete(p.clients, entries[i].key)
			evicted++
		}
	}

	if evicted > 0 {
		slog.Debug("[ClientPool] 清理过期客户端", "evicted", evicted, "remaining", len(p.clients))
	}
}

func (p *ClientPool) closeClientLocked(entry *poolEntry) {
	if entry.client != nil && entry.client.client != nil && entry.client.client.Transport != nil {
		if t, ok := entry.client.client.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
}

func (p *ClientPool) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, entry := range p.clients {
		p.closeClientLocked(entry)
		delete(p.clients, k)
	}
}

func (p *ClientPool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.clients)
}
