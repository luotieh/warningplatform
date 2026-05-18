package nettopo

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

type NetTopoScanner struct {
	client *http.Client
}

func New() *NetTopoScanner {
	return &NetTopoScanner{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
		},
	}
}

func (m *NetTopoScanner) ID() string       { return "nettopo" }
func (m *NetTopoScanner) Name() string     { return "网络拓扑探测" }
func (m *NetTopoScanner) Category() string { return "recon" }

func (m *NetTopoScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	concurrency := core.GetConfigInt(config, "concurrency", 5)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(target *core.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := m.analyzeTarget(ctx, target)
			mu.Lock()
			result.Findings = append(result.Findings, findings...)
			mu.Unlock()
		}(t)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] 网络拓扑探测完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)
	return result, nil
}

func (m *NetTopoScanner) analyzeTarget(ctx context.Context, target *core.Target) []*core.Finding {
	var findings []*core.Finding

	host := target.Host
	if host == "" {
		host = target.IP
	}
	if host == "" {
		return nil
	}

	findings = append(findings, m.dnsResolve(ctx, target, host)...)
	findings = append(findings, m.detectCDN(ctx, target, host)...)
	findings = append(findings, m.detectLoadBalancer(ctx, target, host)...)
	findings = append(findings, m.reverseIP(ctx, target, host)...)
	findings = append(findings, m.traceroute(ctx, target, host)...)

	return findings
}

func (m *NetTopoScanner) dnsResolve(ctx context.Context, target *core.Target, host string) []*core.Finding {
	if net.ParseIP(host) != nil {
		return nil
	}

	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}

	var findings []*core.Finding

	if len(ips) > 1 {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "dns_multi_ip",
			Title:       fmt.Sprintf("DNS多IP解析: %s → %d个IP", host, len(ips)),
			Description: fmt.Sprintf("解析到: %s (可能使用负载均衡/CDN)", strings.Join(ips, ", ")),
			Severity:    "info",
			Confidence:  90,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"host":  host,
				"ips":   strings.Join(ips, ","),
				"count": fmt.Sprintf("%d", len(ips)),
			},
		})
	}

	cnames, err := net.DefaultResolver.LookupCNAME(ctx, host)
	if err == nil && cnames != "" && cnames != host+"." {
		findings = append(findings, &core.Finding{
			ModuleID:   m.ID(),
			Target:     target,
			Type:       "dns_cname",
			Title:      fmt.Sprintf("CNAME记录: %s → %s", host, cnames),
			Severity:   "info",
			Confidence: 95,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"host":  host,
				"cname": cnames,
			},
		})
	}

	nss, err := net.DefaultResolver.LookupNS(ctx, host)
	if err == nil && len(nss) > 0 {
		nsNames := make([]string, 0, len(nss))
		for _, ns := range nss {
			nsNames = append(nsNames, ns.Host)
		}
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "dns_nameservers",
			Title:       fmt.Sprintf("NS记录: %d 台权威DNS", len(nss)),
			Description: strings.Join(nsNames, ", "),
			Severity:    "info",
			Confidence:  95,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"nameservers": strings.Join(nsNames, ","),
			},
		})
	}

	return findings
}

var cdnProviders = []struct {
	name    string
	cname   []string
	headers map[string]string
}{
	{"Cloudflare", []string{"cloudflare"}, map[string]string{"CF-RAY": "", "Server": "cloudflare"}},
	{"AWS CloudFront", []string{"cloudfront.net"}, map[string]string{"X-Amz-Cf-Pop": ""}},
	{"Akamai", []string{"akamai", "edgekey", "edgesuite"}, map[string]string{"X-Akamai-Transformed": ""}},
	{"Fastly", []string{"fastly"}, map[string]string{"X-Served-By": "cache-"}},
	{"Azure CDN", []string{"azureedge.net"}, nil},
	{"Google CDN", []string{"googleusercontent", "gstatic"}, nil},
	{"阿里云CDN", []string{"alicdn", "kunlun"}, nil},
	{"腾讯云CDN", []string{"cdn.dnsv1.com"}, nil},
	{"百度云CDN", []string{"bdydns"}, nil},
	{"七牛CDN", []string{"qiniudns"}, nil},
}

func (m *NetTopoScanner) detectCDN(ctx context.Context, target *core.Target, host string) []*core.Finding {
	if net.ParseIP(host) != nil {
		return nil
	}

	cname, _ := net.DefaultResolver.LookupCNAME(ctx, host)
	lowerCname := strings.ToLower(cname)

	for _, cdn := range cdnProviders {
		for _, pattern := range cdn.cname {
			if strings.Contains(lowerCname, pattern) {
				return []*core.Finding{{
					ModuleID:    m.ID(),
					Target:      target,
					Type:        "cdn_detected",
					Title:       fmt.Sprintf("CDN检测: %s", cdn.name),
					Description: fmt.Sprintf("CNAME %s 指向 %s CDN", cname, cdn.name),
					Severity:    "info",
					Confidence:  85,
					Timestamp:   time.Now(),
					Data: map[string]string{
						"cdn":   cdn.name,
						"cname": cname,
					},
				}}
			}
		}
	}

	baseURL := "http://" + host
	if target.Port == 443 {
		baseURL = "https://" + host
	}
	resp, _ := m.sendRequest(ctx, baseURL)
	if resp != nil {
		for _, cdn := range cdnProviders {
			if cdn.headers == nil {
				continue
			}
			for header, expected := range cdn.headers {
				val := resp.Header.Get(header)
				if val != "" && (expected == "" || strings.Contains(strings.ToLower(val), strings.ToLower(expected))) {
					return []*core.Finding{{
						ModuleID:    m.ID(),
						Target:      target,
						Type:        "cdn_detected",
						Title:       fmt.Sprintf("CDN检测: %s (via header)", cdn.name),
						Description: fmt.Sprintf("Header %s: %s", header, val),
						Severity:    "info",
						Confidence:  80,
						Timestamp:   time.Now(),
						Data: map[string]string{
							"cdn":    cdn.name,
							"header": header,
							"value":  val,
						},
					}}
				}
			}
		}
	}

	return nil
}

func (m *NetTopoScanner) detectLoadBalancer(ctx context.Context, target *core.Target, host string) []*core.Finding {
	baseURL := "http://" + host
	if target.Port == 443 || target.Port == 8443 {
		baseURL = "https://" + host
	} else if target.Port > 0 && target.Port != 80 {
		baseURL = fmt.Sprintf("http://%s:%d", host, target.Port)
	}

	serverValues := make(map[string]int)
	for i := 0; i < 5; i++ {
		resp, _ := m.sendRequest(ctx, baseURL)
		if resp != nil {
			server := resp.Header.Get("Server")
			if server != "" {
				serverValues[server]++
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(serverValues) > 1 {
		servers := make([]string, 0, len(serverValues))
		for s := range serverValues {
			servers = append(servers, s)
		}
		return []*core.Finding{{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "load_balancer_detected",
			Title:       fmt.Sprintf("负载均衡检测: %d个不同Server头", len(serverValues)),
			Description: fmt.Sprintf("5次请求检测到不同的Server值: %s", strings.Join(servers, ", ")),
			Severity:    "info",
			Confidence:  70,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"servers": strings.Join(servers, ","),
			},
		}}
	}

	return nil
}

func (m *NetTopoScanner) reverseIP(ctx context.Context, target *core.Target, host string) []*core.Finding {
	ip := target.IP
	if ip == "" {
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil
		}
		ip = ips[0]
	}

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return nil
	}

	return []*core.Finding{{
		ModuleID:   m.ID(),
		Target:     target,
		Type:       "reverse_dns",
		Title:      fmt.Sprintf("反向DNS: %s → %s", ip, strings.Join(names, ", ")),
		Severity:   "info",
		Confidence: 85,
		Timestamp:  time.Now(),
		Data: map[string]string{
			"ip":    ip,
			"names": strings.Join(names, ","),
		},
	}}
}

func (m *NetTopoScanner) sendRequest(ctx context.Context, rawURL string) (*http.Response, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return resp, string(body)
}
