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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/core"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// ScreenshotConfig 截图分辨率与质量参数。
type ScreenshotConfig struct {
	Width   int // 视口宽度，默认 1920
	Height  int // 视口高度，默认 1080
	Quality int // JPEG 质量 1-100，默认 80
}

func (c ScreenshotConfig) resolvedWidth() int {
	if c.Width > 0 {
		return c.Width
	}
	return 1920
}
func (c ScreenshotConfig) resolvedHeight() int {
	if c.Height > 0 {
		return c.Height
	}
	return 1080
}
func (c ScreenshotConfig) resolvedQuality() int {
	if c.Quality > 0 {
		return c.Quality
	}
	return 80
}

type ScreenshotModule struct {
	client *http.Client
	Config ScreenshotConfig
}

func New() *ScreenshotModule {
	return NewWithConfig(ScreenshotConfig{})
}

func NewWithConfig(cfg ScreenshotConfig) *ScreenshotModule {
	return &ScreenshotModule{
		Config: cfg,
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

func (m *ScreenshotModule) resolveConfig(runtime map[string]interface{}) ScreenshotConfig {
	cfg := m.Config
	if runtime != nil {
		if v, ok := runtime["screenshot_width"].(float64); ok && v > 0 {
			cfg.Width = int(v)
		}
		if v, ok := runtime["screenshot_height"].(float64); ok && v > 0 {
			cfg.Height = int(v)
		}
		if v, ok := runtime["screenshot_quality"].(float64); ok && v > 0 {
			cfg.Quality = int(v)
		}
	}
	return cfg
}

func (m *ScreenshotModule) ID() string       { return "screenshot" }
func (m *ScreenshotModule) Name() string     { return "Web 首页截图" }
func (m *ScreenshotModule) Category() string { return "recon" }

func (m *ScreenshotModule) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	cfg := m.resolveConfig(config)
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
			go func(target *core.Target, u string) {
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
					info.screenshotB64 = captureScreenshot(ctx, browser, u, cfg)
				}

				mu.Lock()
				result.Findings = append(result.Findings, &core.Finding{
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

var browserFallbackPaths = []string{
	`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
	`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	`/usr/bin/microsoft-edge`,
	`/usr/bin/microsoft-edge-stable`,
	`/usr/bin/chromium-browser`,
	`/usr/bin/chromium`,
	`/usr/bin/google-chrome`,
	`/usr/bin/google-chrome-stable`,
}

func findBrowserPath() string {
	if env := os.Getenv("CHROME_BIN"); env != "" {
		if _, err := exec.LookPath(env); err == nil {
			return env
		}
	}
	if path, found := launcher.LookPath(); found {
		return path
	}
	for _, p := range browserFallbackPaths {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	return ""
}

func newLauncher(path, userDataDir string) *launcher.Launcher {
	return launcher.New().Bin(path).
		Headless(true).
		UserDataDir(userDataDir).
		Set("no-sandbox").
		Set("disable-gpu").
		Set("disable-software-rasterizer").
		Set("disable-gpu-compositing").
		Set("ignore-certificate-errors").
		Set("disable-dev-shm-usage").
		Set("disable-extensions").
		Set("disable-background-networking").
		Set("disable-default-apps").
		Set("no-first-run").
		Set("no-default-browser-check").
		Set("disable-features", "EdgeCollections,msEdgeSidebarV2,msEdgeWalletCheckout,msEdgeWorkspacesRedesign,VaapiVideoDecoder,Vulkan,UseSkiaRenderer").
		Set("use-gl", "swiftshader").
		Set("disable-vulkan").
		Set("disable-dbus")
}

func initBrowser() *rod.Browser {
	path := findBrowserPath()
	if path == "" {
		slog.Warn("[-] 未找到 Chrome/Chromium/Edge，跳过页面截图")
		return nil
	}
	slog.Info("[*] 使用浏览器进行截图", "path", path)

	userDataDir := filepath.Join(os.TempDir(), fmt.Sprintf("vulnscan-rod-%d", os.Getpid()))
	_ = os.RemoveAll(userDataDir)

	l := newLauncher(path, userDataDir)
	l.Logger(os.Stderr)
	u, err := l.Launch()
	if err != nil {
		slog.Warn("[-] 启动浏览器失败，跳过页面截图", "error", err, "path", path)
		_ = os.RemoveAll(userDataDir)
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

func captureScreenshot(ctx context.Context, browser *rod.Browser, rawURL string, cfg ScreenshotConfig) string {
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
		Width: cfg.resolvedWidth(), Height: cfg.resolvedHeight(), DeviceScaleFactor: 1,
	})

	quality := cfg.resolvedQuality()
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

func (m *ScreenshotModule) buildURLs(t *core.Target) []string {
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
