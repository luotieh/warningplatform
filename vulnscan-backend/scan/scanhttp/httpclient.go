package scanhttp

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RedirectPolicy int

const (
	RedirectFollow   RedirectPolicy = iota // follow up to MaxRedirects
	RedirectNoFollow                       // never follow redirects
)

type ClientConfig struct {
	Timeout             time.Duration
	DialTimeout         time.Duration
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxRedirects        int
	RedirectPolicy      RedirectPolicy
	MaxResponseBody     int64
	UserAgent           string
	AuthHeaders         map[string]string
	AuthCookies         []*http.Cookie
}

var defaultClientConfig = ClientConfig{
	Timeout:             15 * time.Second,
	DialTimeout:         5 * time.Second,
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 10,
	MaxRedirects:        3,
	RedirectPolicy:      RedirectFollow,
	MaxResponseBody:     256 * 1024,
	UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

type ScanHTTPClient struct {
	client      *http.Client
	config      ClientConfig
	retryAfter  map[string]time.Time
	retryMu     sync.RWMutex
	authHeaders map[string]string
	authCookies []*http.Cookie
	rateLimiter *TokenBucket
}

func NewScanHTTPClient(opts ...ClientOption) *ScanHTTPClient {
	cfg := defaultClientConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	sc := &ScanHTTPClient{
		config:      cfg,
		retryAfter:  make(map[string]time.Time),
		authHeaders: cfg.AuthHeaders,
		authCookies: cfg.AuthCookies,
		rateLimiter: GetGlobalBucket(),
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

	sc.client = &http.Client{
		Timeout:       cfg.Timeout,
		Transport:     transport,
		CheckRedirect: redirectFn,
	}

	return sc
}

type ClientOption func(*ClientConfig)

func WithTimeout(d time.Duration) ClientOption {
	return func(c *ClientConfig) { c.Timeout = d }
}

func WithDialTimeout(d time.Duration) ClientOption {
	return func(c *ClientConfig) { c.DialTimeout = d }
}

func WithMaxIdleConns(n int) ClientOption {
	return func(c *ClientConfig) { c.MaxIdleConns = n }
}

func WithMaxIdleConnsPerHost(n int) ClientOption {
	return func(c *ClientConfig) { c.MaxIdleConnsPerHost = n }
}

func WithRedirectPolicy(p RedirectPolicy) ClientOption {
	return func(c *ClientConfig) { c.RedirectPolicy = p }
}

func WithMaxRedirects(n int) ClientOption {
	return func(c *ClientConfig) { c.MaxRedirects = n }
}

func WithMaxResponseBody(n int64) ClientOption {
	return func(c *ClientConfig) { c.MaxResponseBody = n }
}

func WithUserAgent(ua string) ClientOption {
	return func(c *ClientConfig) { c.UserAgent = ua }
}

func WithAuthHeaders(headers map[string]string) ClientOption {
	return func(c *ClientConfig) { c.AuthHeaders = headers }
}

func WithAuthCookies(cookies []*http.Cookie) ClientOption {
	return func(c *ClientConfig) { c.AuthCookies = cookies }
}

func (sc *ScanHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if sc.rateLimiter != nil {
		if err := sc.rateLimiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}

	host := req.URL.Hostname()

	sc.retryMu.RLock()
	until, throttled := sc.retryAfter[host]
	sc.retryMu.RUnlock()
	if throttled && time.Now().Before(until) {
		time.Sleep(time.Until(until))
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", sc.config.UserAgent)
	}
	for k, v := range sc.authHeaders {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	for _, cookie := range sc.authCookies {
		req.AddCookie(cookie)
	}

	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 429 {
		sc.handleRetryAfter(host, resp)
	}

	return resp, nil
}

func (sc *ScanHTTPClient) handleRetryAfter(host string, resp *http.Response) {
	retryAfter := resp.Header.Get("Retry-After")
	var waitDuration time.Duration

	if retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil {
			waitDuration = time.Duration(seconds) * time.Second
		} else if t, err := http.ParseTime(retryAfter); err == nil {
			waitDuration = time.Until(t)
		}
	}

	if waitDuration <= 0 {
		waitDuration = 10 * time.Second
	}
	if waitDuration > 60*time.Second {
		waitDuration = 60 * time.Second
	}

	sc.retryMu.Lock()
	sc.retryAfter[host] = time.Now().Add(waitDuration)
	sc.retryMu.Unlock()

	slog.Warn("[HTTPClient] 目标限流(429)", "host", host, "retry_after", waitDuration)
}

func (sc *ScanHTTPClient) Fetch(req *http.Request) (string, int, error) {
	resp, err := sc.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, sc.config.MaxResponseBody))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

func (sc *ScanHTTPClient) FetchFull(req *http.Request) (*http.Response, string, error) {
	resp, err := sc.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, sc.config.MaxResponseBody))
	if err != nil {
		return resp, "", err
	}
	return resp, string(body), nil
}

func ClientFromConfig(config map[string]interface{}) []ClientOption {
	var opts []ClientOption

	if headers, ok := config["auth_headers"].(map[string]string); ok && len(headers) > 0 {
		opts = append(opts, WithAuthHeaders(headers))
	}
	if rawHeaders, ok := config["auth_headers"].(map[string]interface{}); ok && len(rawHeaders) > 0 {
		headers := make(map[string]string)
		for k, v := range rawHeaders {
			if s, ok := v.(string); ok {
				headers[k] = s
			}
		}
		if len(headers) > 0 {
			opts = append(opts, WithAuthHeaders(headers))
		}
	}

	if cookieStr, ok := config["auth_cookies"].(string); ok && cookieStr != "" {
		var cookies []*http.Cookie
		for _, part := range strings.Split(cookieStr, ";") {
			part = strings.TrimSpace(part)
			if idx := strings.IndexByte(part, '='); idx > 0 {
				cookies = append(cookies, &http.Cookie{
					Name:  strings.TrimSpace(part[:idx]),
					Value: strings.TrimSpace(part[idx+1:]),
				})
			}
		}
		if len(cookies) > 0 {
			opts = append(opts, WithAuthCookies(cookies))
		}
	}

	if bearer, ok := config["auth_bearer"].(string); ok && bearer != "" {
		opts = append(opts, WithAuthHeaders(map[string]string{
			"Authorization": "Bearer " + bearer,
		}))
	}

	return opts
}

func (sc *ScanHTTPClient) RawClient() *http.Client {
	return sc.client
}
