package proxy

import (
	"net/http"
	"time"
)

type Proxy struct {
	ID        string    `json:"id"`
	Protocol  string    `json:"protocol"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Username  string    `json:"username,omitempty"`
	Password  string    `json:"password,omitempty"`
	Source    string    `json:"source"`
	Anonymity string    `json:"anonymity"`
	Country   string    `json:"country"`
	Latency   int       `json:"latency_ms"`
	Score     int       `json:"score"`
	LastCheck time.Time `json:"last_check"`
	Alive     bool      `json:"alive"`
	UsedCount int       `json:"used_count"`
	FailCount int       `json:"fail_count"`
	BannedFor []string  `json:"banned_for,omitempty"`
}

type ProxyProvider interface {
	Name() string
	Fetch() ([]Proxy, error)
}

type ProxySelector interface {
	Select(pool []*Proxy, target string) *Proxy
}

type ProxiedTransport interface {
	RoundTripper(proxy *Proxy) http.RoundTripper
}
