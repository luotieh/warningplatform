package webcrawl

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gocolly/colly/v2"

	"vulnscan-backend/scan/core"
)

type WebCrawler struct{}

func New() *WebCrawler { return &WebCrawler{} }

func (m *WebCrawler) ID() string       { return "web_crawl" }
func (m *WebCrawler) Name() string     { return "Web 爬虫" }
func (m *WebCrawler) Category() string { return "recon" }

type WebPageInfo struct {
	URL        string
	StatusCode int
	Title      string
	Banner     string
	Server     string
	PoweredBy  string
	TechHints  []string
}

type CrawlResult struct {
	URLs     []string
	Forms    []FormInfo
	Scripts  []string
	Emails   []string
	Comments []string
	Pages    []WebPageInfo
}

type FormInfo struct {
	Action string
	Method string
	Inputs []InputInfo
}

type InputInfo struct {
	Name  string
	Type  string
	Value string
}

func (m *WebCrawler) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	maxDepth := parseInt(config, "max_depth", 3)
	maxPages := parseInt(config, "max_pages", 200)
	concurrency := parseInt(config, "concurrency", 10)
	scope := parseString(config, "scope", "subdomain")
	respectRobots := parseBool(config, "respect_robots", true)

	var mu sync.Mutex
	var totalCrawled atomic.Int64

	for _, t := range targets {
		baseURL := buildBaseURL(t)
		if baseURL == "" {
			continue
		}

		cr := m.crawlSite(ctx, baseURL, maxDepth, maxPages, concurrency, scope, respectRobots, &totalCrawled)

		mu.Lock()
		for _, u := range cr.URLs {
			result.Findings = append(result.Findings, &core.Finding{
				ModuleID:         m.ID(),
				Target:           t,
				Type:             "url",
				Title:            fmt.Sprintf("发现URL: %s", truncate(u, 100)),
				Severity:         "info",
				Confidence:       90,
				ConfidenceReason: "爬虫实际请求获得 HTTP 响应，URL 已验证可达",
				Timestamp:        time.Now(),
				Data:             map[string]string{"url": u},
			})
		}

		for _, form := range cr.Forms {
			var inputs []string
			for _, inp := range form.Inputs {
				inputs = append(inputs, inp.Name+"("+inp.Type+")")
			}
			data := map[string]string{
				"action": form.Action,
				"method": form.Method,
				"inputs": strings.Join(inputs, ","),
			}

			if form.Method == "POST" && len(form.Inputs) > 0 {
				data["content_type"] = "application/x-www-form-urlencoded"
				var pairs []string
				for _, inp := range form.Inputs {
					if inp.Name != "" {
						val := inp.Value
						if val == "" {
							val = "test"
						}
						pairs = append(pairs, url.QueryEscape(inp.Name)+"="+url.QueryEscape(val))
					}
				}
				data["request_body"] = strings.Join(pairs, "&")
			}

			result.Findings = append(result.Findings, &core.Finding{
				ModuleID:         m.ID(),
				Target:           t,
				Type:             "form",
				Title:            fmt.Sprintf("发现表单: %s %s", form.Method, form.Action),
				Severity:         "info",
				Confidence:       85,
				ConfidenceReason: "HTML DOM 解析提取的 <form> 元素，参数来自 <input> 标签",
				Timestamp:        time.Now(),
				Data:             data,
			})
		}

		for _, js := range cr.Scripts {
			result.Findings = append(result.Findings, &core.Finding{
				ModuleID:         m.ID(),
				Target:           t,
				Type:             "script",
				Title:            fmt.Sprintf("发现JS: %s", truncate(js, 100)),
				Severity:         "info",
				Confidence:       90,
				ConfidenceReason: "HTML DOM 解析提取的 <script> src 属性",
				Timestamp:        time.Now(),
				Data:             map[string]string{"url": js},
			})
		}

		for _, email := range cr.Emails {
			result.Findings = append(result.Findings, &core.Finding{
				ModuleID:         m.ID(),
				Target:           t,
				Type:             "email",
				Title:            fmt.Sprintf("发现邮箱: %s", email),
				Severity:         "low",
				Confidence:       80,
				ConfidenceReason: "正则表达式从页面内容提取，未验证邮箱有效性",
				Timestamp:        time.Now(),
				Data:             map[string]string{"email": email},
			})
		}

		for _, page := range cr.Pages {
			titleDisplay := page.Title
			if titleDisplay == "" {
				titleDisplay = page.URL
			}
			result.Findings = append(result.Findings, &core.Finding{
				ModuleID:         m.ID(),
				Target:           t,
				Type:             "web_page",
				Title:            fmt.Sprintf("[%d] %s", page.StatusCode, titleDisplay),
				Severity:         "info",
				Confidence:       95,
				ConfidenceReason: fmt.Sprintf("HTTP 请求直接验证：状态码 %d + 响应头 + 页面内容", page.StatusCode),
				Timestamp:        time.Now(),
				Data: map[string]string{
					"url":         page.URL,
					"status_code": fmt.Sprintf("%d", page.StatusCode),
					"title":       page.Title,
					"banner":      page.Banner,
					"server":      page.Server,
					"powered_by":  page.PoweredBy,
				},
			})
		}
		result.Targets = append(result.Targets, deriveVulnTargets(t, cr)...)
		mu.Unlock()
	}

	result.Duration = time.Since(start)
	slog.Info("[+] Web爬虫完成",
		"pages_crawled", totalCrawled.Load(),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
var commentRe = regexp.MustCompile(`<!--([\s\S]*?)-->`)

func (m *WebCrawler) crawlSite(ctx context.Context, baseURL string, maxDepth, maxPages, concurrency int, scope string, respectRobots bool, crawled *atomic.Int64) *CrawlResult {
	cr := &CrawlResult{}
	var mu sync.Mutex

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return cr
	}

	allowedDomains := buildAllowedDomains(parsedBase, scope)

	c := colly.NewCollector(
		colly.MaxDepth(maxDepth),
		colly.Async(true),
	)

	if len(allowedDomains) > 0 {
		c.AllowedDomains = allowedDomains
	}

	if !respectRobots {
		c.IgnoreRobotsTxt = true
	}

	c.WithTransport(&http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	})

	c.SetRequestTimeout(15 * time.Second)
	if err := c.Limit(&colly.LimitRule{DomainGlob: "*", Parallelism: concurrency}); err != nil {
		slog.Warn("设置并发限制失败", "error", err)
	}

	c.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"

	visited := &safeSet{m: make(map[string]struct{})}

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		if int(crawled.Load()) >= maxPages {
			return
		}
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if link == "" || visited.has(link) {
			return
		}
		if !shouldVisit(link) {
			return
		}
		visited.add(link)
		mu.Lock()
		cr.URLs = append(cr.URLs, link)
		mu.Unlock()
		_ = e.Request.Visit(link)
	})

	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		src := e.Request.AbsoluteURL(e.Attr("src"))
		if src != "" {
			mu.Lock()
			cr.Scripts = append(cr.Scripts, src)
			mu.Unlock()
		}
	})

	c.OnHTML("link[href]", func(e *colly.HTMLElement) {
		href := e.Request.AbsoluteURL(e.Attr("href"))
		if href != "" && !visited.has(href) {
			visited.add(href)
			mu.Lock()
			cr.URLs = append(cr.URLs, href)
			mu.Unlock()
		}
	})

	c.OnHTML("form", func(e *colly.HTMLElement) {
		action := e.Request.AbsoluteURL(e.Attr("action"))
		if action == "" {
			action = e.Request.URL.String()
		}
		method := strings.ToUpper(e.Attr("method"))
		if method == "" {
			method = "GET"
		}

		form := FormInfo{Action: action, Method: method}

		e.ForEach("input, textarea, select", func(_ int, el *colly.HTMLElement) {
			name := el.Attr("name")
			if name != "" {
				form.Inputs = append(form.Inputs, InputInfo{
					Name:  name,
					Type:  el.Attr("type"),
					Value: el.Attr("value"),
				})
			}
		})

		mu.Lock()
		cr.Forms = append(cr.Forms, form)
		mu.Unlock()
	})

	var titleRe = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

	c.OnResponse(func(r *colly.Response) {
		crawled.Add(1)

		contentType := r.Headers.Get("Content-Type")
		isHTML := strings.Contains(contentType, "text/html") || strings.Contains(contentType, "text/xml")

		if isHTML {
			pageURL := r.Request.URL.String()
			body := string(r.Body)

			title := ""
			if m := titleRe.FindStringSubmatch(body); len(m) > 1 {
				title = strings.TrimSpace(m[1])
			}

			var bannerParts []string
			for _, key := range []string{
				"Server", "X-Powered-By", "Content-Type",
				"X-Frame-Options", "X-Content-Type-Options",
				"Strict-Transport-Security", "Set-Cookie",
				"Transfer-Encoding", "Connection", "Cache-Control",
				"Date", "Via", "X-Cache",
			} {
				if v := r.Headers.Get(key); v != "" {
					bannerParts = append(bannerParts, key+": "+v)
				}
			}

			statusLine := fmt.Sprintf("HTTP/1.1 %d %s", r.StatusCode, http.StatusText(r.StatusCode))
			banner := statusLine + "\n" + strings.Join(bannerParts, "\n")

			page := WebPageInfo{
				URL:        pageURL,
				StatusCode: r.StatusCode,
				Title:      title,
				Banner:     banner,
				Server:     r.Headers.Get("Server"),
				PoweredBy:  r.Headers.Get("X-Powered-By"),
			}

			mu.Lock()
			cr.Pages = append(cr.Pages, page)
			mu.Unlock()

			emailMatches := emailRe.FindAllString(body, -1)
			seen := make(map[string]struct{})
			mu.Lock()
			for _, em := range emailMatches {
				lower := strings.ToLower(em)
				if _, ok := seen[lower]; !ok {
					seen[lower] = struct{}{}
					cr.Emails = append(cr.Emails, lower)
				}
			}
			mu.Unlock()

			for _, match := range commentRe.FindAllStringSubmatch(body, -1) {
				if len(match) > 1 {
					comment := strings.TrimSpace(match[1])
					if len(comment) > 10 && len(comment) < 500 {
						mu.Lock()
						cr.Comments = append(cr.Comments, comment)
						mu.Unlock()
					}
				}
			}
		}
	})

	c.OnRequest(func(r *colly.Request) {
		select {
		case <-ctx.Done():
			r.Abort()
		default:
		}
	})

	if err := c.Visit(baseURL); err != nil {
		slog.Warn("爬虫启动失败", "url", baseURL, "error", err)
	}
	c.Wait()

	return cr
}

func shouldVisit(link string) bool {
	lower := strings.ToLower(link)
	skipExts := []string{".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".pdf", ".zip", ".tar",
		".gz", ".mp3", ".mp4", ".avi", ".wmv", ".woff", ".woff2", ".ttf", ".eot"}
	for _, ext := range skipExts {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "data:") || strings.HasPrefix(lower, "tel:") {
		return false
	}
	return true
}

func buildAllowedDomains(base *url.URL, scope string) []string {
	host := base.Hostname()
	switch scope {
	case "strict":
		return []string{host}
	case "subdomain":
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			rootDomain := strings.Join(parts[len(parts)-2:], ".")
			return []string{host, "*." + rootDomain}
		}
		return []string{host}
	case "domain":
		return nil
	}
	return []string{host}
}

var httpPorts = map[int]bool{
	80: true, 443: true, 8080: true, 8443: true, 8000: true, 8888: true,
	8081: true, 8082: true, 8090: true, 9090: true, 3000: true, 5000: true,
	5173: true, 4200: true, 9000: true, 7001: true, 7002: true,
}

func buildBaseURL(t *core.Target) string {
	if t.URL != "" {
		return strings.TrimRight(t.URL, "/")
	}
	if t.Port <= 0 {
		return ""
	}
	proto := strings.ToLower(t.Protocol)
	if !httpPorts[t.Port] && proto != "http" && proto != "https" &&
		!strings.HasPrefix(proto, "http") {
		return ""
	}
	host := t.Host
	if t.IP != "" {
		host = t.IP
	}
	scheme := "http"
	if t.Port == 443 || t.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, t.Port)
}

type safeSet struct {
	mu sync.RWMutex
	m  map[string]struct{}
}

func (s *safeSet) add(v string)      { s.mu.Lock(); s.m[v] = struct{}{}; s.mu.Unlock() }
func (s *safeSet) has(v string) bool { s.mu.RLock(); _, ok := s.m[v]; s.mu.RUnlock(); return ok }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func parseInt(config map[string]interface{}, key string, def int) int {
	if config != nil {
		if v, ok := config[key]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
	}
	return def
}

func parseString(config map[string]interface{}, key, def string) string {
	if config != nil {
		if v, ok := config[key].(string); ok {
			return v
		}
	}
	return def
}

func parseBool(config map[string]interface{}, key string, def bool) bool {
	if config != nil {
		if v, ok := config[key].(bool); ok {
			return v
		}
	}
	return def
}

func deriveVulnTargets(origin *core.Target, cr *CrawlResult) []*core.Target {
	seen := make(map[string]struct{})
	var targets []*core.Target

	for _, u := range cr.URLs {
		parsed, err := url.Parse(u)
		if err != nil || len(parsed.Query()) == 0 {
			continue
		}
		key := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?params"
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		targets = append(targets, &core.Target{
			Host:     parsed.Hostname(),
			Port:     origin.Port,
			Protocol: origin.Protocol,
			URL:      u,
			Extra:    map[string]string{"method": "GET", "source": "webcrawl"},
		})
	}

	for _, form := range cr.Forms {
		if form.Method != "POST" || len(form.Inputs) == 0 {
			continue
		}
		parsed, err := url.Parse(form.Action)
		if err != nil {
			continue
		}
		key := "POST:" + form.Action
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		var pairs []string
		for _, inp := range form.Inputs {
			if inp.Name != "" {
				val := inp.Value
				if val == "" {
					val = "test"
				}
				pairs = append(pairs, url.QueryEscape(inp.Name)+"="+url.QueryEscape(val))
			}
		}

		targets = append(targets, &core.Target{
			Host:     parsed.Hostname(),
			Port:     origin.Port,
			Protocol: origin.Protocol,
			URL:      form.Action,
			Extra: map[string]string{
				"method":       "POST",
				"content_type": "application/x-www-form-urlencoded",
				"request_body": strings.Join(pairs, "&"),
				"source":       "webcrawl",
			},
		})
	}

	return targets
}
