package scanconfig

import (
	"sync"

	"gorm.io/gorm"
)

// Config 全局扫描配置 — 消灭硬编码
type Config struct {
	mu sync.RWMutex

	// HTTP 通用
	UserAgent       string `json:"user_agent" toml:"user_agent"`
	HTTPTimeout     int    `json:"http_timeout" toml:"http_timeout"`
	TLSSkipVerify   bool   `json:"tls_skip_verify" toml:"tls_skip_verify"`
	MaxIdleConns    int    `json:"max_idle_conns" toml:"max_idle_conns"`
	MaxConnsPerHost int    `json:"max_conns_per_host" toml:"max_conns_per_host"`

	// DNS
	DNSServers []string `json:"dns_servers" toml:"dns_servers"`
	DNSTimeout int      `json:"dns_timeout" toml:"dns_timeout"`

	// 端口扫描
	TCPProbePorts    []string `json:"tcp_probe_ports" toml:"tcp_probe_ports"`
	DefaultPortRange string   `json:"default_port_range" toml:"default_port_range"`
	PortScanTimeout  int      `json:"port_scan_timeout" toml:"port_scan_timeout"`
	MaxConcurrency   int      `json:"max_concurrency" toml:"max_concurrency"`
	SYNRateLimit     int      `json:"syn_rate_limit" toml:"syn_rate_limit"`

	// 爬虫
	CrawlMaxDepth      int      `json:"crawl_max_depth" toml:"crawl_max_depth"`
	CrawlMaxPages      int      `json:"crawl_max_pages" toml:"crawl_max_pages"`
	CrawlConcurrency   int      `json:"crawl_concurrency" toml:"crawl_concurrency"`
	CrawlScope         string   `json:"crawl_scope" toml:"crawl_scope"`
	CrawlRespectRobots bool     `json:"crawl_respect_robots" toml:"crawl_respect_robots"`
	SkipExtensions     []string `json:"skip_extensions" toml:"skip_extensions"`

	// WAF 检测
	WAFPayloads []string `json:"waf_payloads" toml:"waf_payloads"`

	// 子域名
	SubdomainResolvers []string `json:"subdomain_resolvers" toml:"subdomain_resolvers"`

	// 私有网段（存活检测）
	PrivateRanges []string `json:"private_ranges" toml:"private_ranges"`
}

var defaultConfig = Config{
	UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0",
	HTTPTimeout:     15,
	TLSSkipVerify:   true,
	MaxIdleConns:    200,
	MaxConnsPerHost: 20,

	DNSServers: []string{
		"8.8.8.8:53", "8.8.4.4:53",
		"1.1.1.1:53", "1.0.0.1:53",
		"223.5.5.5:53", "223.6.6.6:53",
		"114.114.114.114:53", "119.29.29.29:53",
	},
	DNSTimeout: 5,

	TCPProbePorts: []string{
		"80", "443", "22", "3389",
		"8080", "8443", "21", "25",
		"3306", "5432", "6379",
		"9200", "27017",
		"445", "135", "139",
		"53", "8888", "9090",
	},
	DefaultPortRange: "top1000",
	PortScanTimeout:  1,
	MaxConcurrency:   3000,
	SYNRateLimit:     10000,

	CrawlMaxDepth:      3,
	CrawlMaxPages:      200,
	CrawlConcurrency:   10,
	CrawlScope:         "subdomain",
	CrawlRespectRobots: true,
	SkipExtensions: []string{
		".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
		".pdf", ".zip", ".tar", ".gz", ".rar",
		".mp3", ".mp4", ".avi", ".wmv", ".flv",
		".woff", ".woff2", ".ttf", ".eot",
		".doc", ".docx", ".xls", ".xlsx", ".ppt",
	},

	WAFPayloads: []string{
		"/<script>alert(1)</script>",
		"/?id=1' OR '1'='1",
		"/../../etc/passwd",
		"/?cmd=cat+/etc/passwd",
	},

	SubdomainResolvers: []string{
		"8.8.8.8:53", "1.1.1.1:53",
		"223.5.5.5:53", "114.114.114.114:53",
	},

	PrivateRanges: []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	},
}

// ScanConfigModel DB 存储的扫描配置
type ScanConfigModel struct {
	ID    string `gorm:"primarykey;type:varchar(36)" json:"id"`
	Key   string `gorm:"type:varchar(128);uniqueIndex;not null" json:"key"`
	Value string `gorm:"type:text;not null" json:"value"`
	Group string `gorm:"type:varchar(64);index" json:"group"`
	Desc  string `gorm:"type:varchar(256)" json:"desc"`
}

func (ScanConfigModel) TableName() string { return "vs_scan_config" }

// Global 全局配置单例
var (
	global     *Config
	globalOnce sync.Once
)

func Default() *Config {
	globalOnce.Do(func() {
		global = copyDefault()
	})
	return global
}

func copyDefault() *Config {
	d := &defaultConfig
	c := &Config{
		UserAgent:          d.UserAgent,
		HTTPTimeout:        d.HTTPTimeout,
		TLSSkipVerify:      d.TLSSkipVerify,
		MaxIdleConns:       d.MaxIdleConns,
		MaxConnsPerHost:    d.MaxConnsPerHost,
		DNSTimeout:         d.DNSTimeout,
		DefaultPortRange:   d.DefaultPortRange,
		PortScanTimeout:    d.PortScanTimeout,
		MaxConcurrency:     d.MaxConcurrency,
		SYNRateLimit:       d.SYNRateLimit,
		CrawlMaxDepth:      d.CrawlMaxDepth,
		CrawlMaxPages:      d.CrawlMaxPages,
		CrawlConcurrency:   d.CrawlConcurrency,
		CrawlScope:         d.CrawlScope,
		CrawlRespectRobots: d.CrawlRespectRobots,
	}
	c.DNSServers = append([]string{}, d.DNSServers...)
	c.TCPProbePorts = append([]string{}, d.TCPProbePorts...)
	c.SkipExtensions = append([]string{}, d.SkipExtensions...)
	c.WAFPayloads = append([]string{}, d.WAFPayloads...)
	c.SubdomainResolvers = append([]string{}, d.SubdomainResolvers...)
	c.PrivateRanges = append([]string{}, d.PrivateRanges...)
	return c
}

func Init(db *gorm.DB) *Config {
	cfg := Default()
	if db == nil {
		return cfg
	}

	var rows []ScanConfigModel
	if err := db.Find(&rows).Error; err != nil {
		return cfg
	}

	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	for _, row := range rows {
		applyConfigRow(cfg, row)
	}

	return cfg
}

func applyConfigRow(cfg *Config, row ScanConfigModel) {
	switch row.Key {
	case "user_agent":
		cfg.UserAgent = row.Value
	case "http_timeout":
		if v := atoi(row.Value, 0); v > 0 {
			cfg.HTTPTimeout = v
		}
	case "tls_skip_verify":
		cfg.TLSSkipVerify = row.Value == "true"
	case "dns_servers":
		if ss := splitComma(row.Value); len(ss) > 0 {
			cfg.DNSServers = ss
		}
	case "tcp_probe_ports":
		if ss := splitComma(row.Value); len(ss) > 0 {
			cfg.TCPProbePorts = ss
		}
	case "default_port_range":
		if row.Value != "" {
			cfg.DefaultPortRange = row.Value
		}
	case "max_concurrency":
		if v := atoi(row.Value, 0); v > 0 {
			cfg.MaxConcurrency = v
		}
	case "syn_rate_limit":
		if v := atoi(row.Value, 0); v > 0 {
			cfg.SYNRateLimit = v
		}
	case "crawl_max_depth":
		if v := atoi(row.Value, 0); v > 0 {
			cfg.CrawlMaxDepth = v
		}
	case "crawl_max_pages":
		if v := atoi(row.Value, 0); v > 0 {
			cfg.CrawlMaxPages = v
		}
	case "waf_payloads":
		if ss := splitComma(row.Value); len(ss) > 0 {
			cfg.WAFPayloads = ss
		}
	case "subdomain_resolvers":
		if ss := splitComma(row.Value); len(ss) > 0 {
			cfg.SubdomainResolvers = ss
		}
	case "skip_extensions":
		if ss := splitComma(row.Value); len(ss) > 0 {
			cfg.SkipExtensions = ss
		}
	case "private_ranges":
		if ss := splitComma(row.Value); len(ss) > 0 {
			cfg.PrivateRanges = ss
		}
	}
}

// GetUserAgent thread-safe getter
func (c *Config) GetUserAgent() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UserAgent
}

func (c *Config) GetDNSServers() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dst := make([]string, len(c.DNSServers))
	copy(dst, c.DNSServers)
	return dst
}

func (c *Config) GetTCPProbePorts() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dst := make([]string, len(c.TCPProbePorts))
	copy(dst, c.TCPProbePorts)
	return dst
}

func (c *Config) GetWAFPayloads() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dst := make([]string, len(c.WAFPayloads))
	copy(dst, c.WAFPayloads)
	return dst
}

func (c *Config) GetSkipExtensions() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dst := make([]string, len(c.SkipExtensions))
	copy(dst, c.SkipExtensions)
	return dst
}

func (c *Config) GetPrivateRanges() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dst := make([]string, len(c.PrivateRanges))
	copy(dst, c.PrivateRanges)
	return dst
}

func (c *Config) GetSubdomainResolvers() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dst := make([]string, len(c.SubdomainResolvers))
	copy(dst, c.SubdomainResolvers)
	return dst
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, item := range split(s) {
		item = trim(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func split(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trim(s string) string {
	i, j := 0, len(s)-1
	for i <= j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	for j >= i && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
		j--
	}
	return s[i : j+1]
}

func atoi(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 && s != "0" {
		return def
	}
	return n
}
