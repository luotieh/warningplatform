package monitoragent

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"golang.org/x/net/html"
)

type PageService struct {
	client  *http.Client
	browser *rod.Browser
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

	var textBuf strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					snap.Title = strings.TrimSpace(n.FirstChild.Data)
				}
			case "a":
				link := LinkInfo{}
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						link.URL = attr.Val
						if strings.HasPrefix(attr.Val, "http") &&
							!strings.Contains(attr.Val, extractDomain(snap.URL)) {
							link.IsExternal = true
						}
					}
				}
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
					if len(snippet) > 200 {
						snippet = snippet[:200]
					}
					script.Snippet = snippet
				}
				snap.Scripts = append(snap.Scripts, script)
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

	slog.Debug("page parsed",
		"url", snap.URL,
		"title", snap.Title,
		"links", len(snap.Links),
		"scripts", len(snap.Scripts),
		"text_len", len(snap.VisibleText))
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
		_ = ps.browser.Close()
		ps.browser = nil
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

func (ps *PageService) initBrowser() *rod.Browser {
	path := ""
	if env := os.Getenv("CHROME_BIN"); env != "" {
		if _, err := exec.LookPath(env); err == nil {
			path = env
		}
	}
	if path == "" {
		if found, ok := launcher.LookPath(); ok {
			path = found
		}
	}
	if path == "" {
		for _, p := range monitorBrowserFallbackPaths {
			if _, err := exec.LookPath(p); err == nil {
				path = p
				break
			}
		}
	}
	if path == "" {
		slog.Info("[Monitor] 未找到浏览器，监测截图功能不可用")
		return nil
	}

	userDataDir := filepath.Join(os.TempDir(), fmt.Sprintf("monitor-rod-%d", os.Getpid()))
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
		slog.Warn("[Monitor] 启动浏览器失败，监测截图不可用", "error", err)
		_ = os.RemoveAll(userDataDir)
		return nil
	}

	b := rod.New().ControlURL(u)
	if err := b.Connect(); err != nil {
		slog.Warn("[Monitor] 连接浏览器失败", "error", err)
		return nil
	}
	_ = b.IgnoreCertErrors(true)
	slog.Info("[Monitor] 浏览器截图已启用", "path", path)
	return b
}

func (ps *PageService) captureScreenshot(ctx context.Context, rawURL string) []byte {
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

	page = page.Context(ctx).Timeout(20 * time.Second)
	if err := page.Navigate(rawURL); err != nil {
		return nil
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
		slog.Debug("[Monitor] 截图失败", "url", rawURL, "error", err)
		return nil
	}
	return data
}

// CaptureSimpleScreenshot 截取指定 URL 的普通截图（不带标注）。
func (ps *PageService) CaptureSimpleScreenshot(ctx context.Context, rawURL string) []byte {
	return ps.captureScreenshot(ctx, rawURL)
}

// IssueAnnotation 描述需要在截图上标注的问题元素。
type IssueAnnotation struct {
	Type     string   `json:"type"`     // text | link | selector
	Keywords []string `json:"keywords"` // type=text: 需标注的文字; type=link: 需标注的 URL 片段
	Selector string   `json:"selector"` // type=selector: CSS 选择器
	Label    string   `json:"label"`    // 标注说明文字
}

// CaptureAnnotatedScreenshot 导航到指定 URL，根据标注信息在页面上注入红框高亮，然后截图。
func (ps *PageService) CaptureAnnotatedScreenshot(ctx context.Context, rawURL string, annotations []IssueAnnotation) []byte {
	if ps.browser == nil || len(annotations) == 0 {
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

	page = page.Context(ctx).Timeout(25 * time.Second)
	if err := page.Navigate(rawURL); err != nil {
		return nil
	}
	_ = page.WaitStable(800 * time.Millisecond)
	_ = page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width: 1920, Height: 1080, DeviceScaleFactor: 1,
	})

	js := buildAnnotationJS(annotations)
	_, err = page.Timeout(5 * time.Second).Eval(js)
	if err != nil {
		slog.Debug("[Monitor] 注入标注 JS 失败", "url", rawURL, "error", err)
	}

	quality := 80
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
		}
	}

	parts = append(parts, `})()`)
	return strings.Join(parts, "\n")
}

func escapeJSString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
