package realip

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

type RealIPFinder struct {
	client *http.Client
}

func New() *RealIPFinder {
	return &RealIPFinder{
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
		},
	}
}

func (m *RealIPFinder) ID() string       { return "real_ip" }
func (m *RealIPFinder) Name() string     { return "真实IP发现" }
func (m *RealIPFinder) Category() string { return "recon" }

type ipCandidate struct {
	IP         string
	Source     string
	Confidence int
}

func (m *RealIPFinder) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	for _, t := range targets {
		domain := t.Host
		if domain == "" {
			continue
		}

		candidates := m.findRealIP(ctx, domain)

		for _, c := range candidates {
			result.Findings = append(result.Findings, &core.Finding{
				ModuleID:   m.ID(),
				Target:     t,
				Type:       "real_ip",
				Title:      fmt.Sprintf("疑似真实IP: %s (%s)", c.IP, c.Source),
				Severity:   "info",
				Confidence: c.Confidence,
				Timestamp:  time.Now(),
				Data: map[string]string{
					"ip":     c.IP,
					"source": c.Source,
					"domain": domain,
				},
			})
		}
	}

	result.Duration = time.Since(start)
	slog.Info("[+] 真实IP发现完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)
	return result, nil
}

func (m *RealIPFinder) findRealIP(ctx context.Context, domain string) []ipCandidate {
	var mu sync.Mutex
	var wg sync.WaitGroup
	allCandidates := make(map[string]*ipCandidate)

	addCandidate := func(ip, source string, conf int) {
		mu.Lock()
		if existing, ok := allCandidates[ip]; ok {
			existing.Source += "," + source
			if conf > existing.Confidence {
				existing.Confidence = conf
			}
		} else {
			allCandidates[ip] = &ipCandidate{IP: ip, Source: source, Confidence: conf}
		}
		mu.Unlock()
	}

	// 1. 历史 DNS (SecurityTrails 风格 via ViewDNS)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, ip := range m.queryHistoryDNS(ctx, domain) {
			addCandidate(ip, "history_dns", 70)
		}
	}()

	// 2. 常见子域名直连探测
	wg.Add(1)
	go func() {
		defer wg.Done()
		directSubs := []string{
			"direct." + domain, "origin." + domain, "real." + domain,
			"backend." + domain, "server." + domain, "mail." + domain,
			"smtp." + domain, "ftp." + domain, "cpanel." + domain,
			"webmail." + domain, "ns1." + domain, "ns2." + domain,
			"vpn." + domain, "ssh." + domain, "admin." + domain,
			"dev." + domain, "staging." + domain, "test." + domain,
			"api." + domain, "app." + domain, "old." + domain,
		}
		for _, sub := range directSubs {
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, sub)
			if err != nil || len(ips) == 0 {
				continue
			}
			ip := ips[0].IP.String()
			if !isCloudflareIP(ip) {
				addCandidate(ip, "subdomain:"+sub, 65)
			}
		}
	}()

	// 3. MX 记录
	wg.Add(1)
	go func() {
		defer wg.Done()
		mxRecords, err := net.DefaultResolver.LookupMX(ctx, domain)
		if err != nil {
			return
		}
		for _, mx := range mxRecords {
			host := strings.TrimSuffix(mx.Host, ".")
			if strings.HasSuffix(host, domain) {
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil || len(ips) == 0 {
					continue
				}
				addCandidate(ips[0].IP.String(), "mx:"+host, 60)
			}
		}
	}()

	// 4. SPF 记录
	wg.Add(1)
	go func() {
		defer wg.Done()
		txtRecords, err := net.DefaultResolver.LookupTXT(ctx, domain)
		if err != nil {
			return
		}
		for _, txt := range txtRecords {
			if !strings.Contains(txt, "v=spf1") {
				continue
			}
			for _, ip := range extractIPsFromSPF(txt) {
				addCandidate(ip, "spf", 55)
			}
		}
	}()

	// 5. SSL 证书比对
	wg.Add(1)
	go func() {
		defer wg.Done()
		certIPs := m.findIPBySSLCert(ctx, domain)
		for _, ip := range certIPs {
			addCandidate(ip, "ssl_cert_match", 75)
		}
	}()

	wg.Wait()

	var results []ipCandidate
	for _, c := range allCandidates {
		results = append(results, *c)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results
}

func (m *RealIPFinder) queryHistoryDNS(ctx context.Context, domain string) []string {
	apiURL := fmt.Sprintf("https://viewdns.info/iphistory/?domain=%s", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	ipRe := strings.NewReplacer()
	_ = ipRe

	var ips []string
	seen := make(map[string]struct{})

	words := strings.Fields(string(body))
	for _, w := range words {
		w = strings.Trim(w, "<>\"'()[]")
		if isValidIP(w) {
			if _, ok := seen[w]; !ok {
				seen[w] = struct{}{}
				ips = append(ips, w)
			}
		}
	}

	return ips
}

func (m *RealIPFinder) findIPBySSLCert(ctx context.Context, domain string) []string {
	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var candidates []string

	for _, e := range entries {
		names := strings.Split(e.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if name == "" || name == domain {
				continue
			}

			ips, err := net.DefaultResolver.LookupIPAddr(ctx, name)
			if err != nil || len(ips) == 0 {
				continue
			}
			ip := ips[0].IP.String()
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}

			if !isCloudflareIP(ip) {
				candidates = append(candidates, ip)
			}

			if len(candidates) >= 10 {
				return candidates
			}
		}
	}

	return candidates
}

func extractIPsFromSPF(spf string) []string {
	var ips []string
	parts := strings.Fields(spf)
	for _, p := range parts {
		if strings.HasPrefix(p, "ip4:") {
			ip := strings.TrimPrefix(p, "ip4:")
			ip = strings.Split(ip, "/")[0]
			if isValidIP(ip) {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

func isCloudflareIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	cfRanges := []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
		"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
		"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	}
	for _, cidr := range cfRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}
