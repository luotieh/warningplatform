package monitoragent

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"golang.org/x/net/html"
)

type ScreenshotConfig struct {
	Width   int `json:"width"`
	Height  int `json:"height"`
	Quality int `json:"quality"`
}

func DefaultScreenshotConfig() ScreenshotConfig {
	return ScreenshotConfig{Width: 1920, Height: 1080, Quality: 80}
}

type PageService struct {
	client    *http.Client
	browser   *rod.Browser
	ScreenCfg ScreenshotConfig
}

func NewPageService() *PageService {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        50,
		MaxConnsPerHost:     10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	ps := &PageService{
		ScreenCfg: DefaultScreenshotConfig(),
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
	ps.browser = ps.initBrowser()
	return ps
}

const defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func (ps *PageService) FetchPage(ctx context.Context, url string, requestHost ...string) (*PageSnapshot, error) {
	const maxRetries = 3
	var snap *PageSnapshot
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return snap, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
			slog.Debug("[Monitor] FetchPage retry", "url", url, "attempt", attempt+1)
		}

		var err error
		snap, err = ps.fetchPageOnce(ctx, url, requestHost...)
		if err == nil {
			return snap, nil
		}
		lastErr = err

		errStr := err.Error()
		if strings.Contains(errStr, "EOF") ||
			strings.Contains(errStr, "connection reset") ||
			strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "i/o timeout") {
			continue
		}
		return snap, err
	}
	return snap, lastErr
}

func (ps *PageService) fetchPageOnce(ctx context.Context, url string, requestHost ...string) (*PageSnapshot, error) {
	snap := &PageSnapshot{URL: url}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		snap.Error = err.Error()
		return snap, err
	}
	if len(requestHost) > 0 && requestHost[0] != "" {
		req.Host = requestHost[0]
		req.Header.Set("Host", requestHost[0])
	}
	req.Header.Set("User-Agent", defaultUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

	dnsStart := time.Now()
	addrs, err := net.DefaultResolver.LookupHost(ctx, req.URL.Hostname())
	snap.DNSMS = float64(time.Since(dnsStart).Milliseconds())
	if err == nil {
		snap.ResolvedIPs = addrs
	}

	var connectStart, tlsStart time.Time
	var gotConn bool
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { connectStart = time.Now() },
		ConnectDone: func(_, _ string, err error) {
			if err == nil && !connectStart.IsZero() {
				snap.TCPConnectMS = float64(time.Since(connectStart).Milliseconds())
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			if !tlsStart.IsZero() {
				snap.TLSHandshakeMS = float64(time.Since(tlsStart).Milliseconds())
			}
		},
		GotConn: func(info httptrace.GotConnInfo) { gotConn = info.Reused },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	traceTransport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 0,
		}).DialContext,
	}
	traceClient := &http.Client{
		Transport: traceTransport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	defer traceTransport.CloseIdleConnections()

	start := time.Now()
	resp, err := traceClient.Do(req)
	_ = gotConn
	snap.TTFBMS = float64(time.Since(start).Milliseconds())
	if err != nil {
		snap.Error = err.Error()
		return snap, err
	}
	defer resp.Body.Close()

	snap.StatusCode = resp.StatusCode
	snap.FinalURL = resp.Request.URL.String()
	snap.Headers = make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if len(v) > 0 {
			snap.Headers[k] = v[0]
		}
	}

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		ps.extractSSLInfo(snap, resp)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	snap.TotalMS = float64(time.Since(start).Milliseconds())
	if err != nil {
		snap.Error = err.Error()
		return snap, err
	}

	snap.RenderedHTML = string(body)
	snap.ContentLength = int64(len(body))
	snap.ContentHash = fmt.Sprintf("%x", md5.Sum(body))

	ps.parseHTML(snap)

	if ps.browser != nil {
		snap.Screenshot = ps.captureScreenshot(ctx, url)
	}

	return snap, nil
}

func (ps *PageService) parseHTML(snap *PageSnapshot) {
	doc, err := html.Parse(strings.NewReader(snap.RenderedHTML))
	if err != nil {
		return
	}

	pageDomain := extractDomain(snap.URL)
	var textBuf strings.Builder
	var allScriptCode strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					snap.Title = strings.TrimSpace(n.FirstChild.Data)
				}
			case "meta":
				ps.parseMetaRefresh(snap, n)
			case "a":
				link := ps.parseLinkNode(n, pageDomain)
				if link.URL != "" {
					snap.Links = append(snap.Links, link)
				}
			case "script":
				script := ScriptInfo{}
				for _, attr := range n.Attr {
					if attr.Key == "src" {
						script.Src = attr.Val
						script.IsExternal = true
					}
				}
				if !script.IsExternal && n.FirstChild != nil {
					snippet := n.FirstChild.Data
					allScriptCode.WriteString(snippet)
					allScriptCode.WriteString("\n")
					if len(snippet) > 500 {
						snippet = snippet[:500]
					}
					script.Snippet = snippet
				}
				snap.Scripts = append(snap.Scripts, script)
			case "iframe":
				iframe := ps.parseIframeNode(n, pageDomain)
				snap.Iframes = append(snap.Iframes, iframe)
			case "style", "noscript":
				return
			}
		}

		if n.Type == html.TextNode {
			text := strings.TrimSpace(n.Data)
			if text != "" {
				textBuf.WriteString(text)
				textBuf.WriteString(" ")
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)
	snap.VisibleText = strings.TrimSpace(textBuf.String())
	if snap.VisibleText == "" {
		raw := strings.TrimSpace(snap.RenderedHTML)
		if raw != "" {
			snap.VisibleText = raw
		}
	}

	snap.JSRedirects = detectJSRedirects(allScriptCode.String())

	slog.Debug("page parsed",
		"url", snap.URL,
		"title", snap.Title,
		"links", len(snap.Links),
		"scripts", len(snap.Scripts),
		"iframes", len(snap.Iframes),
		"js_redirects", len(snap.JSRedirects),
		"text_len", len(snap.VisibleText))
}

func (ps *PageService) parseMetaRefresh(snap *PageSnapshot, n *html.Node) {
	httpEquiv := ""
	content := ""
	for _, attr := range n.Attr {
		switch strings.ToLower(attr.Key) {
		case "http-equiv":
			httpEquiv = strings.ToLower(attr.Val)
		case "content":
			content = attr.Val
		}
	}
	if httpEquiv != "refresh" || content == "" {
		return
	}
	secs, url := parseMetaRefreshContent(content)
	if url != "" {
		snap.MetaRedirect = &MetaRedirect{URL: url, Seconds: secs}
	}
}

func parseMetaRefreshContent(content string) (int, string) {
	content = strings.TrimSpace(content)
	parts := strings.SplitN(content, ";", 2)
	secs := 0
	if len(parts) >= 1 {
		fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &secs)
	}
	if len(parts) < 2 {
		return secs, ""
	}
	urlPart := strings.TrimSpace(parts[1])
	if strings.HasPrefix(strings.ToLower(urlPart), "url=") {
		urlPart = strings.TrimSpace(urlPart[4:])
		urlPart = strings.Trim(urlPart, "'\"")
		return secs, urlPart
	}
	return secs, ""
}

func (ps *PageService) parseLinkNode(n *html.Node, pageDomain string) LinkInfo {
	link := LinkInfo{}
	style := ""
	for _, attr := range n.Attr {
		switch attr.Key {
		case "href":
			link.URL = attr.Val
			if strings.HasPrefix(attr.Val, "http") &&
				!strings.Contains(attr.Val, pageDomain) {
				link.IsExternal = true
			}
		case "style":
			style = strings.ToLower(attr.Val)
		}
	}
	if isHiddenByStyle(style) {
		link.IsHidden = true
	}
	return link
}

func (ps *PageService) parseIframeNode(n *html.Node, pageDomain string) IframeInfo {
	iframe := IframeInfo{}
	style := ""
	for _, attr := range n.Attr {
		switch attr.Key {
		case "src":
			iframe.Src = attr.Val
			if strings.HasPrefix(attr.Val, "http") &&
				!strings.Contains(attr.Val, pageDomain) {
				iframe.IsExternal = true
			}
		case "width":
			iframe.Width = attr.Val
		case "height":
			iframe.Height = attr.Val
		case "style":
			style = attr.Val
			iframe.Style = attr.Val
		}
	}
	if isHiddenIframe(iframe, style) {
		iframe.IsHidden = true
	}
	return iframe
}

func isHiddenByStyle(style string) bool {
	lower := strings.ToLower(style)
	if strings.Contains(lower, "display:none") || strings.Contains(lower, "display: none") {
		return true
	}
	if strings.Contains(lower, "visibility:hidden") || strings.Contains(lower, "visibility: hidden") {
		return true
	}
	if strings.Contains(lower, "opacity:0") || strings.Contains(lower, "opacity: 0") {
		return true
	}
	if strings.Contains(lower, "font-size:0") || strings.Contains(lower, "font-size: 0") {
		return true
	}
	if strings.Contains(lower, "position:absolute") || strings.Contains(lower, "position: absolute") {
		if strings.Contains(lower, "left:-") || strings.Contains(lower, "top:-") {
			return true
		}
	}
	return false
}

func isHiddenIframe(iframe IframeInfo, style string) bool {
	if isHiddenByStyle(style) {
		return true
	}
	if (iframe.Width == "0" || iframe.Width == "1") &&
		(iframe.Height == "0" || iframe.Height == "1") {
		return true
	}
	return false
}

func extractDomain(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rawURL = rawURL[idx+3:]
	}
	if idx := strings.Index(rawURL, "/"); idx >= 0 {
		rawURL = rawURL[:idx]
	}
	if idx := strings.Index(rawURL, ":"); idx >= 0 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}

func (ps *PageService) extractSSLInfo(snap *PageSnapshot, resp *http.Response) {
	state := resp.TLS
	cert := state.PeerCertificates[0]
	now := time.Now()

	snap.SSLValid = now.Before(cert.NotAfter) && now.After(cert.NotBefore)
	snap.SSLIssuer = cert.Issuer.CommonName
	snap.SSLSubject = cert.Subject.CommonName
	snap.SSLExpiry = cert.NotAfter
	snap.SSLNotBefore = cert.NotBefore
	snap.SSLDaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	snap.SSLSerialNumber = cert.SerialNumber.Text(16)
	snap.SSLSignatureAlg = cert.SignatureAlgorithm.String()

	snap.SSLSAN = cert.DNSNames
	for _, ip := range cert.IPAddresses {
		snap.SSLSAN = append(snap.SSLSAN, ip.String())
	}

	switch state.Version {
	case tls.VersionTLS10:
		snap.SSLProtocol = "TLS 1.0"
	case tls.VersionTLS11:
		snap.SSLProtocol = "TLS 1.1"
	case tls.VersionTLS12:
		snap.SSLProtocol = "TLS 1.2"
	case tls.VersionTLS13:
		snap.SSLProtocol = "TLS 1.3"
	default:
		snap.SSLProtocol = fmt.Sprintf("0x%04x", state.Version)
	}

	snap.SSLCipher = tls.CipherSuiteName(state.CipherSuite)

	if cert.PublicKey != nil {
		switch key := cert.PublicKey.(type) {
		case interface{ Size() int }:
			snap.SSLKeyBits = key.Size() * 8
		default:
			_ = key
		}
	}

	snap.SSLChainDepth = len(state.PeerCertificates)
	snap.SSLChainComplete = len(state.PeerCertificates) > 1

	var sslErrors []string
	if now.After(cert.NotAfter) {
		sslErrors = append(sslErrors, "证书已过期")
	}
	if now.Before(cert.NotBefore) {
		sslErrors = append(sslErrors, "证书尚未生效")
	}
	if snap.SSLDaysLeft <= 7 && snap.SSLDaysLeft > 0 {
		sslErrors = append(sslErrors, fmt.Sprintf("证书将在 %d 天内过期", snap.SSLDaysLeft))
	}
	if state.Version < tls.VersionTLS12 {
		sslErrors = append(sslErrors, "TLS版本过低（低于1.2）")
	}

	host := extractDomain(snap.URL)
	if !certMatchesHost(cert, host) {
		sslErrors = append(sslErrors, "证书域名不匹配")
	}

	snap.SSLErrors = sslErrors
}

func certMatchesHost(cert *x509.Certificate, host string) bool {
	for _, name := range cert.DNSNames {
		if matchDomain(name, host) {
			return true
		}
	}
	if cert.Subject.CommonName != "" {
		return matchDomain(cert.Subject.CommonName, host)
	}
	return false
}

func matchDomain(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		idx := strings.Index(host, ".")
		if idx >= 0 && host[idx:] == suffix {
			return true
		}
	}
	return false
}

func (ps *PageService) Close() {
	ps.client.CloseIdleConnections()
	if ps.browser != nil {
		closeBrowser(ps.browser)
		ps.browser = nil
	}
}

// closeBrowser 安全关闭浏览器实例：连接失效后 rod 的 Close 会对内部
// websocket 指针解引用导致 SIGSEGV（崩溃重启），这里统一用 recover 兜底。
func closeBrowser(b *rod.Browser) {
	defer func() { _ = recover() }()
	if b != nil {
		_ = b.Close()
	}
}

var monitorBrowserFallbackPaths = []string{
	`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
	`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	`/usr/bin/microsoft-edge`,
	`/usr/bin/microsoft-edge-stable`,
	`/usr/bin/chromium-browser`,
	`/usr/bin/chromium`,
	`/usr/bin/google-chrome`,
	`/usr/bin/google-chrome-stable`,
}

func (ps *PageService) findBrowserPath() string {
	if env := os.Getenv("CHROME_BIN"); env != "" {
		if _, err := exec.LookPath(env); err == nil {
			return env
		}
	}
	if found, ok := launcher.LookPath(); ok {
		return found
	}
	for _, p := range monitorBrowserFallbackPaths {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	return ""
}

func (ps *PageService) initBrowser() *rod.Browser {
	path := ps.findBrowserPath()
	if path == "" {
		slog.Info("[Monitor] 未找到浏览器，监测截图功能不可用")
		return nil
	}

	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		b := ps.tryLaunchBrowser(path, attempt)
		if b != nil {
			return b
		}
		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
	}

	slog.Warn("[Monitor] 浏览器多次启动均失败，截图不可用", "path", path, "attempts", maxAttempts)
	return nil
}

func (ps *PageService) tryLaunchBrowser(path string, attempt int) *rod.Browser {
	userDataDir := filepath.Join(os.TempDir(), fmt.Sprintf("monitor-rod-%d-%d", os.Getpid(), attempt))
	_ = os.RemoveAll(userDataDir)

	l := launcher.New().Bin(path).
		Headless(true).
		UserDataDir(userDataDir).
		Set("no-sandbox").
		Set("disable-gpu").
		Set("ignore-certificate-errors").
		Set("disable-dev-shm-usage").
		Set("disable-extensions").
		Set("disable-background-networking").
		Set("disable-default-apps").
		Set("no-first-run").
		Set("no-default-browser-check")

	u, err := l.Launch()
	if err != nil {
		slog.Warn("[Monitor] 启动浏览器失败", "attempt", attempt, "error", err)
		_ = os.RemoveAll(userDataDir)
		return nil
	}

	b := rod.New().ControlURL(u)
	if err := b.Connect(); err != nil {
		slog.Warn("[Monitor] 连接浏览器失败", "attempt", attempt, "error", err)
		_ = os.RemoveAll(userDataDir)
		return nil
	}
	_ = b.IgnoreCertErrors(true)
	slog.Info("[Monitor] 浏览器截图已启用", "path", path, "attempt", attempt)
	return b
}

// EnsureBrowser 确保浏览器实例可用。如果当前实例为 nil 或已失效，尝试重新启动。
func (ps *PageService) EnsureBrowser() {
	if ps.browser != nil {
		if _, err := ps.browser.Version(); err == nil {
			return
		}
		closeBrowser(ps.browser)
		ps.browser = nil
	}
	ps.browser = ps.initBrowser()
}

func (ps *PageService) captureScreenshot(ctx context.Context, rawURL string) []byte {
	ps.EnsureBrowser()
	if ps.browser == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Debug("[Monitor] 截图异常恢复", "url", rawURL, "error", r)
		}
	}()

	page, err := ps.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil
	}
	defer page.Close()

	cfg := ps.ScreenCfg
	page = page.Context(ctx).Timeout(20 * time.Second)
	if err := page.Navigate(rawURL); err != nil {
		return nil
	}
	_ = page.WaitStable(800 * time.Millisecond)
	_ = page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width: cfg.Width, Height: cfg.Height, DeviceScaleFactor: 1,
	})

	quality := cfg.Quality
	data, err := page.Screenshot(false, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatJpeg,
		Quality: &quality,
	})
	if err != nil {
		slog.Debug("[Monitor] 截图失败", "url", rawURL, "error", err)
		return nil
	}
	return data
}

// HasBrowser 返回无头浏览器是否可用。
func (ps *PageService) HasBrowser() bool {
	return ps.browser != nil
}

var cloakingUAs = []struct {
	Name string
	UA   string
}{
	{"Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
	{"Baiduspider", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"},
	{"Bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
}

// CloakingResult records the outcome of a UA-based cloaking detection.
type CloakingResult struct {
	Detected   bool             `json:"detected"`
	NormalHash string           `json:"normal_hash"`
	BotResults []CloakingBotHit `json:"bot_results,omitempty"`
	Similarity float64          `json:"similarity,omitempty"`
}

// CloakingBotHit records a single bot UA test result.
type CloakingBotHit struct {
	BotName     string  `json:"bot_name"`
	ContentHash string  `json:"content_hash"`
	Similarity  float64 `json:"similarity"`
	TitleMatch  bool    `json:"title_match"`
	BotTitle    string  `json:"bot_title,omitempty"`
}

// DetectCloaking fetches the same URL with a normal UA and multiple bot UAs,
// then compares the content to detect SEO cloaking.
func (ps *PageService) DetectCloaking(ctx context.Context, rawURL, normalHash, normalTitle, normalText string) *CloakingResult {
	result := &CloakingResult{NormalHash: normalHash}
	normalSimhash := Simhash(normalText)

	for _, bot := range cloakingUAs {
		botSnap := ps.fetchWithUA(ctx, rawURL, bot.UA)
		if botSnap == nil || botSnap.Error != "" {
			continue
		}

		// 4xx/5xx responses to bot UA are normal anti-crawl behavior, not cloaking
		if botSnap.StatusCode >= 400 {
			slog.Debug("[Monitor] Cloaking跳过：爬虫收到拒绝响应",
				"bot", bot.Name, "status", botSnap.StatusCode, "url", rawURL)
			continue
		}

		botText := botSnap.VisibleText
		if botText == "" {
			botText = botSnap.RenderedHTML
		}
		botSimhash := Simhash(botText)
		sim := SimhashSimilarity(normalSimhash, botSimhash)

		hit := CloakingBotHit{
			BotName:     bot.Name,
			ContentHash: botSnap.ContentHash,
			Similarity:  sim,
			TitleMatch:  botSnap.Title == normalTitle,
			BotTitle:    botSnap.Title,
		}
		result.BotResults = append(result.BotResults, hit)

		if sim < 0.70 || botSnap.ContentHash != normalHash {
			result.Detected = true
			result.Similarity = sim
		}
	}

	return result
}

func (ps *PageService) fetchWithUA(ctx context.Context, rawURL, ua string) *PageSnapshot {
	snap := &PageSnapshot{URL: rawURL}
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		snap.Error = err.Error()
		return snap
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := ps.client.Do(req)
	if err != nil {
		snap.Error = err.Error()
		return snap
	}
	defer resp.Body.Close()

	snap.StatusCode = resp.StatusCode
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		snap.Error = err.Error()
		return snap
	}

	snap.RenderedHTML = string(body)
	snap.ContentHash = fmt.Sprintf("%x", md5.Sum(body))
	ps.parseHTML(snap)
	return snap
}

// Simhash wrapper for page_service (delegates to analyzer.Simhash logic).
func Simhash(text string) uint64 {
	tokens := simhashTokenize(text)
	if len(tokens) == 0 {
		return 0
	}
	var v [64]int
	for _, token := range tokens {
		h := simhashHash(token)
		for i := 0; i < 64; i++ {
			if (h>>uint(i))&1 == 1 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}
	var fp uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			fp |= 1 << uint(i)
		}
	}
	return fp
}

func SimhashSimilarity(a, b uint64) float64 {
	if a == 0 && b == 0 {
		return 1.0
	}
	x := a ^ b
	dist := 0
	for x != 0 {
		dist++
		x &= x - 1
	}
	return 1.0 - float64(dist)/64.0
}

func simhashTokenize(text string) []string {
	text = strings.ToLower(text)
	fields := strings.Fields(text)
	if len(fields) < 3 {
		return fields
	}
	ngrams := make([]string, 0, len(fields))
	ngrams = append(ngrams, fields...)
	for i := 0; i <= len(fields)-3; i++ {
		ngrams = append(ngrams, fields[i]+" "+fields[i+1]+" "+fields[i+2])
	}
	return ngrams
}

func simhashHash(token string) uint64 {
	h := md5.Sum([]byte(token))
	return binary.LittleEndian.Uint64(h[:8])
}

// DetectBrowserRedirect navigates to the URL with a headless browser and monitors
// for JS-triggered navigation. It waits up to `waitDuration` after initial load
// to detect delayed redirects. Returns the final URL and whether a redirect occurred.
func (ps *PageService) DetectBrowserRedirect(ctx context.Context, rawURL string, waitDuration time.Duration) (finalURL string, redirected bool) {
	ps.EnsureBrowser()
	if ps.browser == nil {
		return rawURL, false
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Debug("[Monitor] 浏览器跳转检测异常", "url", rawURL, "error", r)
		}
	}()

	page, err := ps.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return rawURL, false
	}
	defer page.Close()

	page = page.Context(ctx).Timeout(waitDuration + 10*time.Second)
	_ = page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width: 1920, Height: 1080, DeviceScaleFactor: 1,
	})

	if err := page.Navigate(rawURL); err != nil {
		return rawURL, false
	}
	_ = page.WaitStable(800 * time.Millisecond)

	info, err := page.Info()
	if err == nil && info.URL != "" {
		immediateURL := info.URL
		origDomain := extractDomain(rawURL)
		immDomain := extractDomain(immediateURL)
		if origDomain != immDomain && immDomain != "" {
			return immediateURL, true
		}
	}

	if waitDuration > 0 {
		select {
		case <-ctx.Done():
			return rawURL, false
		case <-time.After(waitDuration):
		}

		info, err = page.Info()
		if err == nil && info.URL != "" {
			delayedURL := info.URL
			origDomain := extractDomain(rawURL)
			delayDomain := extractDomain(delayedURL)
			if origDomain != delayDomain && delayDomain != "" {
				slog.Info("[Monitor] 检测到延迟JS跳转", "original", rawURL, "redirected_to", delayedURL)
				return delayedURL, true
			}
		}
	}

	return rawURL, false
}

// CaptureSimpleScreenshot 截取指定 URL 的普通截图（不带标注）。
func (ps *PageService) CaptureSimpleScreenshot(ctx context.Context, rawURL string) []byte {
	return ps.captureScreenshot(ctx, rawURL)
}

// IssueAnnotation 描述需要在截图上标注的问题元素。
type IssueAnnotation struct {
	Type     string   `json:"type"`     // text | link | selector | page
	Keywords []string `json:"keywords"` // type=text: 需标注的文字; type=link: 需标注的 URL 片段
	Selector string   `json:"selector"` // type=selector: CSS 选择器
	Label    string   `json:"label"`    // 标注说明文字
}

// CaptureAnnotatedScreenshot 导航到指定 URL，根据标注信息在页面上注入红框高亮，然后截图。
func (ps *PageService) CaptureAnnotatedScreenshot(ctx context.Context, rawURL string, annotations []IssueAnnotation) []byte {
	if len(annotations) == 0 {
		return nil
	}
	ps.EnsureBrowser()
	if ps.browser == nil {
		slog.Warn("[Monitor] 标注截图跳过：无可用浏览器", "url", rawURL)
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Debug("[Monitor] 标注截图异常恢复", "url", rawURL, "error", r)
		}
	}()

	page, err := ps.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil
	}
	defer page.Close()

	cfg := ps.ScreenCfg
	page = page.Context(ctx).Timeout(25 * time.Second)
	if err := page.Navigate(rawURL); err != nil {
		return nil
	}
	_ = page.WaitStable(800 * time.Millisecond)
	_ = page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width: cfg.Width, Height: cfg.Height, DeviceScaleFactor: 1,
	})

	js := buildAnnotationJS(annotations)
	_, err = page.Timeout(5 * time.Second).Eval(js)
	if err != nil {
		slog.Debug("[Monitor] 注入标注 JS 失败", "url", rawURL, "error", err)
	}

	quality := cfg.Quality
	data, err := page.Screenshot(false, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatJpeg,
		Quality: &quality,
	})
	if err != nil {
		slog.Debug("[Monitor] 标注截图失败", "url", rawURL, "error", err)
		return nil
	}
	return data
}

func buildAnnotationJS(annotations []IssueAnnotation) string {
	var parts []string

	parts = append(parts, `(function(){
const STYLE='outline:3px solid red;outline-offset:2px;background:rgba(255,0,0,0.08);position:relative;';
const BADGE_STYLE='position:absolute;top:-18px;right:0;background:red;color:#fff;font-size:11px;padding:1px 6px;border-radius:3px;z-index:99999;white-space:nowrap;pointer-events:none;';
const PAGE_BORDER_STYLE='position:fixed;inset:10px;border:4px solid #ef4444;border-radius:8px;box-shadow:0 0 0 9999px rgba(239,68,68,0.08),0 0 24px rgba(239,68,68,0.45);z-index:2147483646;pointer-events:none;';
const PAGE_BADGE_STYLE='position:fixed;top:18px;left:18px;background:#dc2626;color:#fff;font:600 14px/1.4 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:7px 12px;border-radius:6px;box-shadow:0 8px 24px rgba(0,0,0,0.22);z-index:2147483647;pointer-events:none;';
let marked=0;

function addBadge(el, text){
  if(!text) return;
  const b=document.createElement('span');
  b.style.cssText=BADGE_STYLE;
  b.textContent=text;
  const pos=getComputedStyle(el).position;
  if(pos==='static') el.style.position='relative';
  el.appendChild(b);
}

function highlightTextNodes(root, keyword, label){
  const walker=document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
  const matches=[];
  while(walker.nextNode()){
    const node=walker.currentNode;
    if(node.nodeValue && node.nodeValue.includes(keyword)){
      matches.push(node);
    }
  }
  matches.forEach(node=>{
    const parent=node.parentElement;
    if(!parent||parent.tagName==='SCRIPT'||parent.tagName==='STYLE') return;
    const idx=node.nodeValue.indexOf(keyword);
    if(idx<0) return;
    const before=node.nodeValue.substring(0,idx);
    const match=node.nodeValue.substring(idx,idx+keyword.length);
    const after=node.nodeValue.substring(idx+keyword.length);
    const mark=document.createElement('mark');
    mark.style.cssText=STYLE+'display:inline;';
    mark.textContent=match;
    if(label&&marked<10) addBadge(mark, label);
    marked++;
    const frag=document.createDocumentFragment();
    if(before) frag.appendChild(document.createTextNode(before));
    frag.appendChild(mark);
    if(after) frag.appendChild(document.createTextNode(after));
    parent.replaceChild(frag, node);
  });
}

function highlightLinks(urlFragments, label){
  document.querySelectorAll('a').forEach(a=>{
    const href=a.href||a.getAttribute('href')||'';
    for(const frag of urlFragments){
      if(href.includes(frag)){
        a.style.cssText+=STYLE;
        if(label&&marked<10) addBadge(a, label);
        marked++;
        break;
      }
    }
  });
}

function highlightSelector(sel, label){
  document.querySelectorAll(sel).forEach(el=>{
    el.style.cssText+=STYLE;
    if(label&&marked<10) addBadge(el, label);
    marked++;
  });
}

function highlightPage(label){
  const border=document.createElement('div');
  border.style.cssText=PAGE_BORDER_STYLE;
  document.documentElement.appendChild(border);
  if(label){
    const badge=document.createElement('div');
    badge.style.cssText=PAGE_BADGE_STYLE;
    badge.textContent=label;
    document.documentElement.appendChild(badge);
  }
  marked++;
}
`)

	for _, ann := range annotations {
		switch ann.Type {
		case "text":
			for _, kw := range ann.Keywords {
				escaped := escapeJSString(kw)
				label := escapeJSString(ann.Label)
				parts = append(parts, fmt.Sprintf(`highlightTextNodes(document.body, '%s', '%s');`, escaped, label))
			}
		case "link":
			if len(ann.Keywords) > 0 {
				var escaped []string
				for _, kw := range ann.Keywords {
					escaped = append(escaped, "'"+escapeJSString(kw)+"'")
				}
				label := escapeJSString(ann.Label)
				parts = append(parts, fmt.Sprintf(`highlightLinks([%s], '%s');`, strings.Join(escaped, ","), label))
			}
		case "selector":
			if ann.Selector != "" {
				label := escapeJSString(ann.Label)
				parts = append(parts, fmt.Sprintf(`highlightSelector('%s', '%s');`, escapeJSString(ann.Selector), label))
			}
		case "page":
			label := escapeJSString(ann.Label)
			parts = append(parts, fmt.Sprintf(`highlightPage('%s');`, label))
		}
	}

	parts = append(parts, `})()`)
	return strings.Join(parts, "\n")
}

var jsRedirectPatterns = []struct {
	re      *regexp.Regexp
	typName string
}{
	{regexp.MustCompile(`(?i)(?:window\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]`), "location_assign"},
	{regexp.MustCompile(`(?i)location\.replace\s*\(\s*['"]([^'"]+)['"]\s*\)`), "location_replace"},
	{regexp.MustCompile(`(?i)window\.open\s*\(\s*['"]([^'"]+)['"]\s*\)`), "window_open"},
	{regexp.MustCompile(`(?i)window\.navigate\s*\(\s*['"]([^'"]+)['"]\s*\)`), "window_navigate"},
	{regexp.MustCompile(`(?i)document\.location\s*=\s*['"]([^'"]+)['"]`), "document_location"},
}

var jsDelayedRedirectRe = regexp.MustCompile(`(?i)setTimeout\s*\(\s*(?:function\s*\(\s*\)\s*\{[^}]*(?:location|window\.open|navigate)[^}]*\}|['"][^'"]*(?:location|window\.open)[^'"]*['"])\s*,\s*(\d+)`)
var jsSetIntervalRedirectRe = regexp.MustCompile(`(?i)setInterval\s*\(\s*(?:function\s*\(\s*\)\s*\{[^}]*(?:location|window\.open)[^}]*\}|['"][^'"]*(?:location|window\.open)[^'"]*['"])\s*,\s*(\d+)`)

func detectJSRedirects(allScript string) []JSRedirect {
	if allScript == "" {
		return nil
	}

	var redirects []JSRedirect
	seen := make(map[string]bool)

	for _, p := range jsRedirectPatterns {
		matches := p.re.FindAllStringSubmatch(allScript, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			target := m[1]
			if target == "" || target == "#" || target == "about:blank" {
				continue
			}
			key := p.typName + ":" + target
			if seen[key] {
				continue
			}
			seen[key] = true

			snippet := m[0]
			if len(snippet) > 200 {
				snippet = snippet[:200]
			}
			redirects = append(redirects, JSRedirect{
				Type:    p.typName,
				Target:  target,
				Snippet: snippet,
			})
		}
	}

	if dMatches := jsDelayedRedirectRe.FindAllStringSubmatch(allScript, -1); len(dMatches) > 0 {
		for _, m := range dMatches {
			delay := 0
			if len(m) > 1 {
				fmt.Sscanf(m[1], "%d", &delay)
			}
			snippet := m[0]
			if len(snippet) > 200 {
				snippet = snippet[:200]
			}
			redirects = append(redirects, JSRedirect{
				Type:    "setTimeout_redirect",
				Target:  "",
				Snippet: snippet,
				Delay:   delay,
			})
		}
	}

	if iMatches := jsSetIntervalRedirectRe.FindAllStringSubmatch(allScript, -1); len(iMatches) > 0 {
		for _, m := range iMatches {
			delay := 0
			if len(m) > 1 {
				fmt.Sscanf(m[1], "%d", &delay)
			}
			snippet := m[0]
			if len(snippet) > 200 {
				snippet = snippet[:200]
			}
			redirects = append(redirects, JSRedirect{
				Type:    "setInterval_redirect",
				Target:  "",
				Snippet: snippet,
				Delay:   delay,
			})
		}
	}

	return redirects
}

func escapeJSString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
