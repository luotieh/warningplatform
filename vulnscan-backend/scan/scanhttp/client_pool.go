package scanhttp

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	globalClientPool     *ClientPool
	globalClientPoolOnce sync.Once
)

type ClientPool struct {
	defaultClient *ScanHTTPClient
	clients       map[string]*ScanHTTPClient
	mu            sync.RWMutex
	config        ClientConfig
}

func GetGlobalClientPool() *ClientPool {
	globalClientPoolOnce.Do(func() {
		globalClientPool = &ClientPool{
			defaultClient: NewScanHTTPClient(),
			clients:       make(map[string]*ScanHTTPClient),
			config:        defaultClientConfig,
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
	client, ok := p.clients[key]
	p.mu.RUnlock()
	if ok {
		return client
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if client, ok = p.clients[key]; ok {
		return client
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

	client = &ScanHTTPClient{
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

	p.clients[key] = client
	return client
}

func (p *ClientPool) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, c := range p.clients {
		if c.client != nil && c.client.Transport != nil {
			if t, ok := c.client.Transport.(*http.Transport); ok {
				t.CloseIdleConnections()
			}
		}
		delete(p.clients, k)
	}
}
