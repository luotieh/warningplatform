package ipattr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/engine"
)

type IPAttributor struct {
	client *http.Client
}

func New() *IPAttributor {
	return &IPAttributor{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (m *IPAttributor) ID() string       { return "ip_attr" }
func (m *IPAttributor) Name() string     { return "IP 归属识别" }
func (m *IPAttributor) Category() string { return "recon" }

type IPInfo struct {
	IP       string
	IsWAF    bool
	IsCDN    bool
	IsCloud  bool
	IsProxy  bool
	Provider string
	ASN      int
	ASNOrg   string
	Country  string
	City     string
	CIDR     string
	RealIP   string
	Evidence []string
}

var cdnCIDRs = []struct {
	name string
	cidr string
}{
	// Cloudflare
	{"Cloudflare", "173.245.48.0/20"},
	{"Cloudflare", "103.21.244.0/22"},
	{"Cloudflare", "103.22.200.0/22"},
	{"Cloudflare", "103.31.4.0/22"},
	{"Cloudflare", "141.101.64.0/18"},
	{"Cloudflare", "108.162.192.0/18"},
	{"Cloudflare", "190.93.240.0/20"},
	{"Cloudflare", "188.114.96.0/20"},
	{"Cloudflare", "197.234.240.0/22"},
	{"Cloudflare", "198.41.128.0/17"},
	{"Cloudflare", "162.158.0.0/15"},
	{"Cloudflare", "104.16.0.0/13"},
	{"Cloudflare", "104.24.0.0/14"},
	{"Cloudflare", "172.64.0.0/13"},
	{"Cloudflare", "131.0.72.0/22"},

	// Fastly
	{"Fastly", "23.235.32.0/20"},
	{"Fastly", "43.249.72.0/22"},
	{"Fastly", "103.244.50.0/24"},
	{"Fastly", "103.245.222.0/23"},
	{"Fastly", "103.245.224.0/24"},
	{"Fastly", "104.156.80.0/20"},
	{"Fastly", "151.101.0.0/16"},
	{"Fastly", "157.52.64.0/18"},

	// Akamai (部分)
	{"Akamai", "23.0.0.0/12"},
	{"Akamai", "23.32.0.0/11"},
	{"Akamai", "23.64.0.0/14"},
	{"Akamai", "23.72.0.0/13"},

	// 阿里云 CDN
	{"阿里云CDN", "47.246.0.0/16"},
	{"阿里云CDN", "47.254.0.0/16"},

	// 腾讯云 CDN
	{"腾讯云CDN", "101.226.0.0/16"},
	{"腾讯云CDN", "101.227.0.0/16"},
}

var cloudASNKeywords = map[string]string{
	"amazon":       "AWS",
	"aws":          "AWS",
	"microsoft":    "Azure",
	"azure":        "Azure",
	"google":       "GCP",
	"alibaba":      "阿里云",
	"alicloud":     "阿里云",
	"aliyun":       "阿里云",
	"tencent":      "腾讯云",
	"huawei":       "华为云",
	"digitalocean": "DigitalOcean",
	"linode":       "Linode",
	"vultr":        "Vultr",
	"hetzner":      "Hetzner",
	"oracle":       "Oracle Cloud",
	"baidu":        "百度云",
}

var cdnASNKeywords = []string{
	"cloudflare", "akamai", "fastly", "cloudfront",
	"incapsula", "sucuri", "stackpath", "keycdn",
	"edgecast", "limelight", "maxcdn", "verizon digital",
	"cdn77", "jsdelivr", "bunny", "gcore",
	"cachefly", "chinacache", "wangsu", "baishan",
}

func (m *IPAttributor) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, t := range targets {
		ip := t.IP
		if ip == "" && t.Host != "" {
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, t.Host)
			if err != nil || len(ips) == 0 {
				continue
			}
			ip = ips[0].IP.String()
		}
		if ip == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target *engine.Target, ipAddr string) {
			defer wg.Done()
			defer func() { <-sem }()

			info := m.analyzeIP(ctx, ipAddr)

			mu.Lock()
			attr := "直连服务器"
			if info.IsCDN {
				attr = "CDN (" + info.Provider + ")"
			} else if info.IsWAF {
				attr = "WAF (" + info.Provider + ")"
			} else if info.IsCloud {
				attr = "云主机 (" + info.Provider + ")"
			} else if info.IsProxy {
				attr = "代理/反向代理"
			}

			result.Findings = append(result.Findings, &engine.Finding{
				ModuleID:   m.ID(),
				Target:     target,
				Type:       "ip_attribution",
				Title:      fmt.Sprintf("IP归属: %s → %s", ipAddr, attr),
				Severity:   "info",
				Confidence: 80,
				Evidence:   strings.Join(info.Evidence, "; "),
				Timestamp:  time.Now(),
				Data: map[string]string{
					"ip":       ipAddr,
					"is_cdn":   fmt.Sprintf("%v", info.IsCDN),
					"is_waf":   fmt.Sprintf("%v", info.IsWAF),
					"is_cloud": fmt.Sprintf("%v", info.IsCloud),
					"provider": info.Provider,
					"asn":      fmt.Sprintf("%d", info.ASN),
					"asn_org":  info.ASNOrg,
					"country":  info.Country,
					"city":     info.City,
				},
			})
			mu.Unlock()
		}(t, ip)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] IP归属识别完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *IPAttributor) analyzeIP(ctx context.Context, ip string) *IPInfo {
	info := &IPInfo{IP: ip}

	if provider := matchCIDR(ip); provider != "" {
		info.IsCDN = true
		info.Provider = provider
		info.Evidence = append(info.Evidence, fmt.Sprintf("CIDR匹配: %s", provider))
	}

	asnInfo := m.queryASNInfo(ctx, ip)
	if asnInfo != nil {
		info.ASN = asnInfo.asn
		info.ASNOrg = asnInfo.org
		info.Country = asnInfo.country
		info.City = asnInfo.city

		orgLower := strings.ToLower(asnInfo.org)

		for keyword, name := range cloudASNKeywords {
			if strings.Contains(orgLower, keyword) {
				info.IsCloud = true
				info.Provider = name
				info.Evidence = append(info.Evidence, fmt.Sprintf("ASN组织匹配云厂商: %s (ASN %d)", name, asnInfo.asn))
				break
			}
		}

		for _, keyword := range cdnASNKeywords {
			if strings.Contains(orgLower, keyword) {
				info.IsCDN = true
				info.Provider = asnInfo.org
				info.Evidence = append(info.Evidence, fmt.Sprintf("ASN组织匹配CDN: %s", asnInfo.org))
				break
			}
		}
	}

	ptrRecords := m.queryPTR(ctx, ip)
	for _, ptr := range ptrRecords {
		ptrLower := strings.ToLower(ptr)
		if strings.Contains(ptrLower, "cdn") || strings.Contains(ptrLower, "cache") || strings.Contains(ptrLower, "edge") {
			info.IsCDN = true
			info.Evidence = append(info.Evidence, fmt.Sprintf("PTR含CDN特征: %s", ptr))
		}
		if strings.Contains(ptrLower, "waf") || strings.Contains(ptrLower, "firewall") || strings.Contains(ptrLower, "shield") {
			info.IsWAF = true
			info.Evidence = append(info.Evidence, fmt.Sprintf("PTR含WAF特征: %s", ptr))
		}
	}

	if len(info.Evidence) == 0 {
		info.Evidence = append(info.Evidence, "未匹配已知CDN/WAF/Cloud，判定为直连服务器")
	}

	return info
}

func matchCIDR(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	for _, entry := range cdnCIDRs {
		_, cidr, err := net.ParseCIDR(entry.cidr)
		if err != nil {
			continue
		}
		if cidr.Contains(parsed) {
			return entry.name
		}
	}

	return ""
}

type asnResult struct {
	asn     int
	org     string
	country string
	city    string
}

func (m *IPAttributor) queryASNInfo(ctx context.Context, ip string) *asnResult {
	apiURL := fmt.Sprintf("https://ipinfo.io/%s/json", ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

	var info struct {
		Org     string `json:"org"`
		Country string `json:"country"`
		City    string `json:"city"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil
	}

	result := &asnResult{
		org:     info.Org,
		country: info.Country,
		city:    info.City,
	}

	parts := strings.SplitN(info.Org, " ", 2)
	if len(parts) > 0 && strings.HasPrefix(parts[0], "AS") {
		asnStr := strings.TrimPrefix(parts[0], "AS")
		for _, c := range asnStr {
			if c < '0' || c > '9' {
				return result
			}
			result.asn = result.asn*10 + int(c-'0')
		}
	}

	return result
}

func (m *IPAttributor) queryPTR(ctx context.Context, ip string) []string {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil
	}
	return names
}
