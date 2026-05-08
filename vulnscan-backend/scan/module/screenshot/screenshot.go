package screenshot

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/engine"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

type ScreenshotModule struct {
	client *http.Client
}

func New() *ScreenshotModule {
	return &ScreenshotModule{
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 5,
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (m *ScreenshotModule) ID() string       { return "screenshot" }
func (m *ScreenshotModule) Name() string     { return "Web 首页截图" }
func (m *ScreenshotModule) Category() string { return "recon" }

func (m *ScreenshotModule) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}

	browser := initBrowser()

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, t := range targets {
		urls := m.buildURLs(t)
		if len(urls) == 0 {
			continue
		}

		for _, rawURL := range urls {
			wg.Add(1)
			sem <- struct{}{}
			go func(target *engine.Target, u string) {
				defer wg.Done()
				defer func() { <-sem }()

				select {
				case <-ctx.Done():
					return
				default:
				}

				info := m.capturePageInfo(ctx, u)
				if info == nil {
					return
				}

				if browser != nil {
					info.screenshotB64 = captureScreenshot(ctx, browser, u)
				}

				mu.Lock()
				result.Findings = append(result.Findings, &engine.Finding{
					ModuleID:   m.ID(),
					Target:     target,
					Type:       "web_page",
					Title:      fmt.Sprintf("Web页面: %s", info.title),
					Severity:   "info",
					Confidence: 90,
					Timestamp:  time.Now(),
					Data:       info.toMap(),
				})
				mu.Unlock()
			}(t, rawURL)
		}
	}

	wg.Wait()

	if browser != nil {
		_ = browser.Close()
	}

	result.Duration = time.Since(start)
	slog.Info("[+] Web页面采集完成", "targets", len(targets), "findings", len(result.Findings), "duration", result.Duration)
	return result, nil
}

func initBrowser() *rod.Browser {
	path, found := launcher.LookPath()
	if !found {
		slog.Warn("[-] 未找到 Chrome/Chromium，跳过页面截图")
		return nil
	}
	u, err := launcher.New().Bin(path).
		Headless(true).
		Set("no-sandbox").
		Set("disable-gpu").
		Set("ignore-certificate-errors").
		Set("disable-dev-shm-usage").
		Launch()
	if err != nil {
		slog.Warn("[-] 启动浏览器失败，跳过页面截图", "error", err)
		return nil
	}
	b := rod.New().ControlURL(u)
	if err := b.Connect(); err != nil {
		slog.Warn("[-] 连接浏览器失败", "error", err)
		return nil
	}
	_ = b.IgnoreCertErrors(true)
	return b
}

func captureScreenshot(ctx context.Context, browser *rod.Browser, rawURL string) string {
	defer func() {
		if r := recover(); r != nil {
			slog.Debug("截图异常恢复", "url", rawURL, "error", r)
		}
	}()

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return ""
	}
	defer page.Close()

	page = page.Context(ctx).Timeout(20 * time.Second)

	if err := page.Navigate(rawURL); err != nil {
		return ""
	}

	_ = page.WaitStable(800 * time.Millisecond)

	_ = page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width: 1280, Height: 720, DeviceScaleFactor: 1,
	})

	quality := 70
	data, err := page.Screenshot(false, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatJpeg,
		Quality: &quality,
	})
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(data)
}

type pageInfo struct {
	url           string
	statusCode    int
	title         string
	server        string
	contentType   string
	redirect      string
	headers       string
	bodySize      int
	bodyPreview   string
	technologies  []string
	screenshotB64 string
}

func (p *pageInfo) toMap() map[string]string {
	m := map[string]string{
		"url":          p.url,
		"status_code":  fmt.Sprintf("%d", p.statusCode),
		"title":        p.title,
		"server":       p.server,
		"content_type": p.contentType,
		"body_size":    fmt.Sprintf("%d", p.bodySize),
	}
	if p.redirect != "" {
		m["redirect"] = p.redirect
	}
	if p.bodyPreview != "" {
		m["body_preview"] = p.bodyPreview
	}
	if len(p.technologies) > 0 {
		m["technologies"] = strings.Join(p.technologies, ",")
	}
	if p.screenshotB64 != "" {
		m["screenshot"] = p.screenshotB64
	}
	return m
}

func (m *ScreenshotModule) capturePageInfo(ctx context.Context, rawURL string) *pageInfo {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := string(body)

	info := &pageInfo{
		url:         rawURL,
		statusCode:  resp.StatusCode,
		server:      resp.Header.Get("Server"),
		contentType: resp.Header.Get("Content-Type"),
		bodySize:    len(body),
	}

	if resp.Request != nil && resp.Request.URL.String() != rawURL {
		info.redirect = resp.Request.URL.String()
	}

	info.title = extractTitle(bodyStr)

	if len(bodyStr) > 2000 {
		info.bodyPreview = bodyStr[:2000]
	} else {
		info.bodyPreview = bodyStr
	}

	info.technologies = detectQuickTech(resp, bodyStr)

	return info
}

func extractTitle(html string) string {
	lower := strings.ToLower(html)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	start = strings.Index(html[start:], ">")
	if start < 0 {
		return ""
	}
	start += strings.Index(lower, "<title") + 1
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return ""
	}
	title := strings.TrimSpace(html[start : start+end])
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

func detectQuickTech(resp *http.Response, body string) []string {
	var techs []string

	server := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(server, "nginx") {
		techs = append(techs, "Nginx")
	}
	if strings.Contains(server, "apache") {
		techs = append(techs, "Apache")
	}
	if strings.Contains(server, "iis") {
		techs = append(techs, "IIS")
	}
	if strings.Contains(server, "openresty") {
		techs = append(techs, "OpenResty")
	}

	powered := strings.ToLower(resp.Header.Get("X-Powered-By"))
	if strings.Contains(powered, "php") {
		techs = append(techs, "PHP")
	}
	if strings.Contains(powered, "asp.net") {
		techs = append(techs, "ASP.NET")
	}
	if strings.Contains(powered, "express") {
		techs = append(techs, "Express.js")
	}

	lower := strings.ToLower(body)
	techPatterns := map[string]string{
		"wp-content": "WordPress",
		"react":      "React",
		"vue":        "Vue.js",
		"angular":    "Angular",
		"jquery":     "jQuery",
		"bootstrap":  "Bootstrap",
		"layui":      "Layui",
		"antd":       "Ant Design",
		"element-ui": "Element UI",
		"naiveui":    "Naive UI",
	}
	for pattern, name := range techPatterns {
		if strings.Contains(lower, pattern) {
			techs = append(techs, name)
		}
	}

	return techs
}

func (m *ScreenshotModule) buildURLs(t *engine.Target) []string {
	if t.URL != "" {
		return []string{t.URL}
	}
	host := t.Host
	if t.IP != "" {
		host = t.IP
	}
	if host == "" {
		return nil
	}

	if t.Port > 0 {
		scheme := "http"
		if t.Port == 443 || t.Port == 8443 {
			scheme = "https"
		}
		return []string{fmt.Sprintf("%s://%s:%d", scheme, host, t.Port)}
	}

	return []string{
		fmt.Sprintf("https://%s", host),
		fmt.Sprintf("http://%s", host),
	}
}
