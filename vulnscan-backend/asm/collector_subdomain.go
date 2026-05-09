package asm

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var commonSubdomains = []string{
	"www", "mail", "ftp", "smtp", "pop", "imap", "dns", "ns1", "ns2",
	"mx", "mx1", "mx2", "webmail", "owa", "vpn", "remote", "portal",
	"admin", "api", "dev", "test", "staging", "uat", "prod", "beta",
	"demo", "docs", "blog", "wiki", "git", "svn", "jenkins", "jira",
	"confluence", "grafana", "prometheus", "kibana", "elastic",
	"db", "mysql", "postgres", "redis", "mongo", "elasticsearch",
	"cdn", "static", "assets", "img", "media", "video", "audio",
	"app", "mobile", "m", "sso", "auth", "login", "register",
	"payment", "billing", "shop", "store", "crm", "erp", "oa",
	"hr", "finance", "monitor", "log", "backup", "ftp", "sftp",
	"ssh", "telnet", "rdp", "vnc", "docker", "k8s", "kubernetes",
	"internal", "intranet", "extranet", "dmz", "proxy", "lb",
	"loadbalancer", "firewall", "gateway", "router", "switch",
}

type SubdomainBruteCollector struct {
	wordlist []string
	maxConns int
	timeout  time.Duration
}

func NewSubdomainBruteCollector(wordlist []string, maxConns int, timeout time.Duration) *SubdomainBruteCollector {
	if len(wordlist) == 0 {
		wordlist = commonSubdomains
	}
	if maxConns <= 0 {
		maxConns = 50
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &SubdomainBruteCollector{
		wordlist: wordlist,
		maxConns: maxConns,
		timeout:  timeout,
	}
}

func (c *SubdomainBruteCollector) Name() string { return "subdomain-brute" }

func (c *SubdomainBruteCollector) Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error) {
	if seed.Type != "domain" {
		return nil, nil
	}

	baseDomain := seed.Value
	var mu sync.Mutex
	var assets []DiscoveredAsset
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.maxConns)

	for _, sub := range c.wordlist {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			fqdn := subdomain + "." + baseDomain

			ips, err := resolveWithTimeout(ctx, fqdn, c.timeout)
			if err != nil || len(ips) == 0 {
				return
			}

			mu.Lock()
			for _, ip := range ips {
				assets = append(assets, DiscoveredAsset{
					Type:   "subdomain",
					Value:  fqdn,
					Source: "subdomain-brute",
					Attributes: map[string]string{
						"parent": baseDomain,
						"ip":     ip,
					},
					FirstSeen: time.Now(),
					LastSeen:  time.Now(),
					Status:    "active",
				})
			}
			mu.Unlock()
		}(sub)
	}

	wg.Wait()
	return assets, nil
}

func resolveWithTimeout(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	ips, err := r.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}

	return ips, nil
}

type PassiveHTTPCollector struct {
	client  *httpWithRedirectClient
	timeout time.Duration
}

type httpWithRedirectClient struct {
	client *http.Client
}

func NewPassiveHTTPCollector(timeout time.Duration) *PassiveHTTPCollector {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &PassiveHTTPCollector{
		client: &httpWithRedirectClient{
			client: &http.Client{
				Timeout: timeout,
				Transport: &http.Transport{
					TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
					DisableKeepAlives: true,
					MaxIdleConns:      50,
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if len(via) >= 5 {
						return fmt.Errorf("stopped after 5 redirects")
					}
					return nil
				},
			},
		},
		timeout: timeout,
	}
}

func (c *PassiveHTTPCollector) Name() string { return "passive-http" }

func (c *PassiveHTTPCollector) Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error) {
	targets := buildPassiveTargets(seed)
	if len(targets) == 0 {
		return nil, nil
	}

	var assets []DiscoveredAsset
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return assets, ctx.Err()
		default:
		}

		result, err := c.fetchPassiveInfo(ctx, target)
		if err != nil {
			continue
		}

		assets = append(assets, result...)
	}

	return assets, nil
}

func buildPassiveTargets(seed Seed) []string {
	var targets []string
	switch seed.Type {
	case "domain":
		targets = append(targets,
			fmt.Sprintf("http://%s/robots.txt", seed.Value),
			fmt.Sprintf("https://%s/robots.txt", seed.Value),
			fmt.Sprintf("http://%s/sitemap.xml", seed.Value),
			fmt.Sprintf("https://%s/sitemap.xml", seed.Value),
			fmt.Sprintf("http://%s/.well-known/security.txt", seed.Value),
			fmt.Sprintf("https://%s/.well-known/security.txt", seed.Value),
		)
	case "ip":
		targets = append(targets,
			fmt.Sprintf("http://%s/robots.txt", seed.Value),
			fmt.Sprintf("https://%s/robots.txt", seed.Value),
		)
	case "subdomain":
		targets = append(targets,
			fmt.Sprintf("http://%s/robots.txt", seed.Value),
			fmt.Sprintf("https://%s/robots.txt", seed.Value),
		)
	}
	return targets
}

func (c *PassiveHTTPCollector) fetchPassiveInfo(ctx context.Context, url string) ([]DiscoveredAsset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; VulnScan/1.0)")

	resp, err := c.client.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))

	var assets []DiscoveredAsset

	if strings.Contains(url, "robots.txt") {
		disallowed := extractDisallowedPaths(string(body))
		if len(disallowed) > 0 {
			assets = append(assets, DiscoveredAsset{
				Type:   "hidden_path",
				Value:  url,
				Source: "passive-http",
				Attributes: map[string]string{
					"target":         extractHost(url),
					"disallowed":     strings.Join(disallowed, ","),
					"disallow_count": fmt.Sprintf("%d", len(disallowed)),
				},
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Status:    "active",
			})
		}
	}

	if strings.Contains(url, "sitemap.xml") {
		urls := extractSitemapURLs(string(body))
		if len(urls) > 0 {
			assets = append(assets, DiscoveredAsset{
				Type:   "sitemap",
				Value:  url,
				Source: "passive-http",
				Attributes: map[string]string{
					"target":    extractHost(url),
					"url_count": fmt.Sprintf("%d", len(urls)),
				},
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Status:    "active",
			})
		}
	}

	if strings.Contains(url, "security.txt") {
		assets = append(assets, DiscoveredAsset{
			Type:   "security_info",
			Value:  url,
			Source: "passive-http",
			Attributes: map[string]string{
				"target":  extractHost(url),
				"content": sanitizeBanner(string(body)),
			},
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Status:    "active",
		})
	}

	return assets, nil
}

func extractDisallowedPaths(robotsTxt string) []string {
	var paths []string
	lines := strings.Split(robotsTxt, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(line[len("disallow:"):])
			if path != "" && path != "/" {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func extractSitemapURLs(sitemapXML string) []string {
	var urls []string
	locRegex := regexp.MustCompile(`<loc>([^<]+)</loc>`)
	matches := locRegex.FindAllStringSubmatch(sitemapXML, -1)
	for _, m := range matches {
		if len(m) > 1 {
			urls = append(urls, m[1])
		}
	}
	return urls
}

func extractHost(url string) string {
	if strings.HasPrefix(url, "https://") {
		url = url[len("https://"):]
	} else if strings.HasPrefix(url, "http://") {
		url = url[len("http://"):]
	}
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	return url
}
