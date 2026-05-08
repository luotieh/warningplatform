package cyberspace

import "time"

// CyberAsset 网络空间测绘资产统一模型
type CyberAsset struct {
	IP       string            `json:"ip"`
	Port     int               `json:"port"`
	Protocol string            `json:"protocol"`
	Service  string            `json:"service"`
	Version  string            `json:"version"`
	Banner   string            `json:"banner"`
	OS       string            `json:"os"`
	Hostname string            `json:"hostname"`
	Domains  []string          `json:"domains"`
	Country  string            `json:"country"`
	City     string            `json:"city"`
	ASN      int               `json:"asn"`
	Org      string            `json:"org"`
	ISP      string            `json:"isp"`
	Title    string            `json:"title"`
	Cert     *CertInfo         `json:"cert,omitempty"`
	Tags     []string          `json:"tags"`
	Source   string            `json:"source"`
	LastSeen time.Time         `json:"last_seen"`
	Extra    map[string]string `json:"extra,omitempty"`
}

type CertInfo struct {
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	SANs       []string `json:"sans"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	Expired    bool     `json:"expired"`
	SelfSigned bool     `json:"self_signed"`
}

// Provider 网络空间测绘平台统一接口
type Provider interface {
	Name() string
	Search(query string, maxResults int) ([]*CyberAsset, error)
	HostLookup(ip string) ([]*CyberAsset, error)
}

// ProviderConfig 平台配置
type ProviderConfig struct {
	APIKey    string `json:"api_key" toml:"api_key"`
	APISecret string `json:"api_secret" toml:"api_secret"`
	BaseURL   string `json:"base_url" toml:"base_url"`
	Enabled   bool   `json:"enabled" toml:"enabled"`
	RateLimit int    `json:"rate_limit" toml:"rate_limit"`
}
