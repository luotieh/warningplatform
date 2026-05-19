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
	"strings"
	"time"

	"golang.org/x/net/html"
)

type PageService struct {
	client *http.Client
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

	return &PageService{
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
}
