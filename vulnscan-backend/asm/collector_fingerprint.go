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
	"time"
)

var (
	serverHeaderRegex  = regexp.MustCompile(`(?i)(nginx|apache|iis|openresty|caddy|lighttpd)`)
	poweredByRegex     = regexp.MustCompile(`(?i)PHP/([\d.]+)`)
	xGeneratorRegex    = regexp.MustCompile(`(?i)(wordpress|drupal|joomla|django|laravel|express|spring|thinkphp)`)
	setCookieRegex     = regexp.MustCompile(`(?i)(phpsessid|jsessionid|asp\.net_sessionid|csrftoken)`)
	titleRegex         = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	metaFrameworkRegex = regexp.MustCompile(`(?i)(vue\.js|react|angular|jquery|bootstrap|tailwind)`)
)

type ServiceFingerprintCollector struct {
	client  *http.Client
	timeout time.Duration
}

func NewServiceFingerprintCollector(timeout time.Duration) *ServiceFingerprintCollector {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &ServiceFingerprintCollector{
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives: true,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		timeout: timeout,
	}
}

func (c *ServiceFingerprintCollector) Name() string { return "service-fingerprint" }

func (c *ServiceFingerprintCollector) Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error) {
	targets := buildFingerprintTargets(seed)
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

		fp, err := c.fingerprintURL(ctx, target)
		if err != nil {
			continue
		}

		assets = append(assets, fp...)
	}

	return assets, nil
}

func buildFingerprintTargets(seed Seed) []string {
	var targets []string
	switch seed.Type {
	case "url":
		targets = append(targets, seed.Value)
	case "domain":
		targets = append(targets,
			fmt.Sprintf("http://%s", seed.Value),
			fmt.Sprintf("https://%s", seed.Value),
		)
	case "ip":
		targets = append(targets,
			fmt.Sprintf("http://%s", seed.Value),
			fmt.Sprintf("https://%s", seed.Value),
		)
	case "port":
		parts := strings.SplitN(seed.Value, ":", 2)
		if len(parts) == 2 {
			targets = append(targets,
				fmt.Sprintf("http://%s", seed.Value),
				fmt.Sprintf("https://%s", seed.Value),
			)
		}
	}
	return targets
}

func (c *ServiceFingerprintCollector) fingerprintURL(ctx context.Context, url string) ([]DiscoveredAsset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	bodyStr := string(body)

	var assets []DiscoveredAsset

	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")
	xGenerator := resp.Header.Get("X-Generator")
	setCookie := resp.Header.Get("Set-Cookie")
	contentType := resp.Header.Get("Content-Type")

	techs := extractTechs(server, poweredBy, xGenerator, setCookie, contentType, bodyStr)

	for _, tech := range techs {
		assets = append(assets, DiscoveredAsset{
			Type:   "tech",
			Value:  tech.Name,
			Source: "service-fingerprint",
			Attributes: map[string]string{
				"target":     url,
				"version":    tech.Version,
				"category":   tech.Category,
				"confidence": tech.Confidence,
				"evidence":   tech.Evidence,
			},
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Status:    "active",
		})
	}

	title := extractTitle(bodyStr)
	if title != "" {
		assets = append(assets, DiscoveredAsset{
			Type:   "web_page",
			Value:  url,
			Source: "service-fingerprint",
			Attributes: map[string]string{
				"title":        title,
				"status_code":  fmt.Sprintf("%d", resp.StatusCode),
				"content_type": contentType,
				"server":       server,
			},
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Status:    "active",
		})
	}

	return assets, nil
}

type techInfo struct {
	Name       string
	Version    string
	Category   string
	Confidence string
	Evidence   string
}

func extractTechs(server, poweredBy, xGenerator, setCookie, contentType, body string) []techInfo {
	var techs []techInfo

	if server != "" {
		if m := serverHeaderRegex.FindStringSubmatch(server); len(m) > 1 {
			techs = append(techs, techInfo{
				Name:       strings.ToLower(m[1]),
				Version:    "",
				Category:   "web-server",
				Confidence: "high",
				Evidence:   fmt.Sprintf("Server: %s", server),
			})
		}
	}

	if poweredBy != "" {
		if m := poweredByRegex.FindStringSubmatch(poweredBy); len(m) > 1 {
			techs = append(techs, techInfo{
				Name:       "php",
				Version:    m[1],
				Category:   "programming-language",
				Confidence: "high",
				Evidence:   fmt.Sprintf("X-Powered-By: %s", poweredBy),
			})
		}
	}

	if xGenerator != "" {
		if m := xGeneratorRegex.FindStringSubmatch(xGenerator); len(m) > 1 {
			techs = append(techs, techInfo{
				Name:       strings.ToLower(m[1]),
				Version:    "",
				Category:   "framework",
				Confidence: "high",
				Evidence:   fmt.Sprintf("X-Generator: %s", xGenerator),
			})
		}
	}

	if setCookie != "" {
		if strings.Contains(strings.ToLower(setCookie), "phpsessid") {
			techs = append(techs, techInfo{
				Name:       "php",
				Version:    "",
				Category:   "programming-language",
				Confidence: "medium",
				Evidence:   fmt.Sprintf("Set-Cookie: PHPSESSID"),
			})
		}
		if strings.Contains(strings.ToLower(setCookie), "jsessionid") {
			techs = append(techs, techInfo{
				Name:       "java",
				Version:    "",
				Category:   "programming-language",
				Confidence: "medium",
				Evidence:   fmt.Sprintf("Set-Cookie: JSESSIONID"),
			})
		}
		if strings.Contains(strings.ToLower(setCookie), "asp.net_sessionid") {
			techs = append(techs, techInfo{
				Name:       "asp.net",
				Version:    "",
				Category:   "framework",
				Confidence: "high",
				Evidence:   fmt.Sprintf("Set-Cookie: ASP.NET_SessionId"),
			})
		}
	}

	if strings.Contains(contentType, "json") {
		techs = append(techs, techInfo{
			Name:       "api",
			Version:    "",
			Category:   "api",
			Confidence: "low",
			Evidence:   fmt.Sprintf("Content-Type: %s", contentType),
		})
	}

	if m := metaFrameworkRegex.FindStringSubmatch(body); len(m) > 1 {
		techs = append(techs, techInfo{
			Name:       strings.ToLower(m[1]),
			Version:    "",
			Category:   "javascript-library",
			Confidence: "medium",
			Evidence:   "meta tag / script reference",
		})
	}

	return techs
}

func extractTitle(body string) string {
	if m := titleRegex.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

type BannerCollector struct {
	timeout time.Duration
}

func NewBannerCollector(timeout time.Duration) *BannerCollector {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &BannerCollector{timeout: timeout}
}

func (c *BannerCollector) Name() string { return "banner-grab" }

func (c *BannerCollector) Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error) {
	if seed.Type != "port" {
		return nil, nil
	}

	parts := strings.SplitN(seed.Value, ":", 2)
	if len(parts) != 2 {
		return nil, nil
	}
	host := parts[0]
	port := parts[1]

	banner, err := grabBanner(ctx, host, port, c.timeout)
	if err != nil {
		return nil, err
	}

	service := identifyService(banner, port)

	return []DiscoveredAsset{
		{
			Type:   "service",
			Value:  seed.Value,
			Source: "banner-grab",
			Attributes: map[string]string{
				"banner":  sanitizeBanner(banner),
				"service": service,
				"port":    port,
			},
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Status:    "active",
		},
	}, nil
}

func grabBanner(ctx context.Context, host, port string, timeout time.Duration) (string, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", host+":"+port)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}

	return string(buf[:n]), nil
}

func identifyService(banner, port string) string {
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "ssh-") {
		return "ssh"
	}
	if strings.Contains(bannerLower, "ftp") {
		return "ftp"
	}
	if strings.Contains(bannerLower, "smtp") {
		return "smtp"
	}
	if strings.Contains(bannerLower, "mysql") {
		return "mysql"
	}
	if strings.Contains(bannerLower, "postgres") {
		return "postgresql"
	}
	if strings.Contains(bannerLower, "redis") {
		return "redis"
	}
	if strings.Contains(bannerLower, "mongodb") {
		return "mongodb"
	}

	return guessServiceByPort(parseInt(port))
}

func sanitizeBanner(banner string) string {
	banner = strings.ReplaceAll(banner, "\r", "")
	banner = strings.ReplaceAll(banner, "\n", " ")
	if len(banner) > 200 {
		banner = banner[:200]
	}
	return strings.TrimSpace(banner)
}

func parseInt(s string) int {
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
