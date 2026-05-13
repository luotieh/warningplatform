package serviceprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/scan/core"
)

// ProbeResult 探测结果
type ProbeResult struct {
	Service    string
	Version    string
	Banner     string
	Method     string
	Confidence int
	HTTPInfo   *HTTPInfo
	TLSInfo    *TLSInfo
	ProbeChain []string
}

// HTTPInfo HTTP 服务详细信息
type HTTPInfo struct {
	Title       string
	Server      string
	XPoweredBy  string
	Framework   string
	CMS         string
	Language    string
	Paths       map[string]int
	Headers     map[string]string
	FaviconHash string
}

// TLSInfo TLS 证书详细信息
type TLSInfo struct {
	CN              string
	SANs            []string
	Organization    []string
	Issuer          string
	NotBefore       time.Time
	NotAfter        time.Time
	IsSelfSigned    bool
	IsExpired       bool
	DaysUntilExpiry int
}

// probeWithChain 多阶段探测链，一次连接多次探测
func (m *ServiceProbe) probeWithChain(ctx context.Context, target *core.Target, timeout time.Duration, enableTLS bool) *ProbeResult {
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}
	addr := net.JoinHostPort(host, strconv.Itoa(target.Port))

	probes := m.store.GetProbes(target.Port)

	if isActiveOnlyPort(target.Port) {
		return m.probeActiveOnlyWithChain(ctx, target, addr, timeout, probes)
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return m.fallbackPortMapWithResult(target)
	}
	defer conn.Close()

	bannerTimeout := timeout / 3
	if bannerTimeout < 800*time.Millisecond {
		bannerTimeout = 800 * time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(bannerTimeout))

	reader := bufio.NewReaderSize(conn, 4096)
	banner := readBanner(reader)

	result := &ProbeResult{Banner: truncate(banner, 512)}

	if banner != "" {
		service, version, matched := m.store.MatchBanner(banner, target.Port)
		if matched {
			result.Service = service
			result.Version = version
			result.Method = "banner_passive"
			result.Confidence = 85
		}
	}

	if result.Service == "" && len(probes) > 0 {
		activeResult := m.probeActiveWithConn(ctx, conn, addr, timeout, probes, target.Port)
		if activeResult != nil {
			result.Service = activeResult.Service
			result.Version = activeResult.Version
			result.Banner = activeResult.Banner
			result.Method = activeResult.Method
			result.Confidence = activeResult.Confidence
		}
	}

	if isHTTPService(result.Service) {
		httpInfo := m.probeHTTPDepth(ctx, target, timeout, result.Service)
		if httpInfo != nil {
			result.HTTPInfo = httpInfo
			if result.Confidence < 90 {
				result.Confidence = 90
			}
		}
	}

	if enableTLS && isTLSPort(target.Port) {
		tlsInfo := m.probeTLS(ctx, addr, target, timeout)
		if tlsInfo != nil {
			result.TLSInfo = tlsInfo
		}
	}

	if result.Service == "" {
		if fallback := m.fallbackPortMapWithResult(target); fallback != nil {
			result.Service = fallback.Service
			result.Method = fallback.Method
			result.Confidence = fallback.Confidence
		}
	}

	return result
}

// probeActiveOnlyWithChain 仅主动探测模式（带探测链）
func (m *ServiceProbe) probeActiveOnlyWithChain(ctx context.Context, target *core.Target, addr string, timeout time.Duration, probes []*CompiledFingerprint) *ProbeResult {
	for _, probe := range probes {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if len(probe.ProbeData) == 0 {
			continue
		}

		dialer := &net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}

		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, werr := conn.Write(probe.ProbeData); werr != nil {
			conn.Close()
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		resp := readBanner(bufio.NewReaderSize(conn, 4096))
		conn.Close()

		if resp == "" {
			continue
		}

		if match := m.matchProbeResponse(probe, resp, target.Port); match != nil {
			result := &ProbeResult{
				Service:    match.Service,
				Version:    match.Version,
				Banner:     match.Banner,
				Method:     match.Method,
				Confidence: match.Confidence,
			}

			if isHTTPService(result.Service) {
				httpInfo := m.probeHTTPDepth(ctx, target, timeout, result.Service)
				if httpInfo != nil {
					result.HTTPInfo = httpInfo
				}
			}

			return result
		}
	}

	return m.fallbackPortMapWithResult(target)
}

// probeActiveWithConn 使用已有连接进行主动探测
func (m *ServiceProbe) probeActiveWithConn(ctx context.Context, conn net.Conn, addr string, timeout time.Duration, probes []*CompiledFingerprint, port int) *ProbeResult {
	for _, probe := range probes {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if len(probe.ProbeData) == 0 {
			continue
		}

		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, werr := conn.Write(probe.ProbeData); werr != nil {
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		resp := readBanner(bufio.NewReaderSize(conn, 4096))

		if resp != "" {
			if match := m.matchProbeResponse(probe, resp, port); match != nil {
				return &ProbeResult{
					Service:    match.Service,
					Version:    match.Version,
					Banner:     match.Banner,
					Method:     match.Method,
					Confidence: match.Confidence,
				}
			}
		}
	}
	return nil
}

// probeHTTPDepth HTTP 深度识别
func (m *ServiceProbe) probeHTTPDepth(ctx context.Context, target *core.Target, timeout time.Duration, service string) *HTTPInfo {
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}

	scheme := "http"
	if strings.Contains(strings.ToLower(service), "https") || target.Port == 443 || target.Port == 8443 {
		scheme = "https"
	}

	baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, target.Port)

	httpInfo := &HTTPInfo{
		Paths:   make(map[string]int),
		Headers: make(map[string]string),
	}

	paths := []string{"/"}
	httpProbes := m.store.GetHTTPProbes(target.Port)
	if len(httpProbes) > 0 {
		paths = nil
		for _, p := range httpProbes {
			if len(p.HTTPPaths) > 0 {
				paths = append(paths, p.HTTPPaths...)
			} else {
				paths = append(paths, "/")
			}
		}
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return httpInfo
		default:
		}

		url := baseURL + path
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; VulnScan/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()

		httpInfo.Paths[path] = resp.StatusCode

		if path == "/" {
			for k, v := range resp.Header {
				if len(v) > 0 {
					httpInfo.Headers[k] = v[0]
				}
			}

			httpInfo.Server = resp.Header.Get("Server")
			httpInfo.XPoweredBy = resp.Header.Get("X-Powered-By")

			bodyStr := string(body)
			httpInfo.Title = extractTitle(bodyStr)

			if fw := m.identifyFramework(resp.Header, bodyStr); fw != "" {
				httpInfo.Framework = fw
			}
			if cms := m.identifyCMS(bodyStr); cms != "" {
				httpInfo.CMS = cms
			}
			if lang := m.identifyLanguage(resp.Header, bodyStr); lang != "" {
				httpInfo.Language = lang
			}
		}
	}

	return httpInfo
}

// probeTLS TLS 证书分析
func (m *ServiceProbe) probeTLS(ctx context.Context, addr string, target *core.Target, timeout time.Duration) *TLSInfo {
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target.Host,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]
	tlsInfo := &TLSInfo{
		CN:           cert.Subject.CommonName,
		Organization: cert.Subject.Organization,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
	}

	for _, name := range cert.DNSNames {
		tlsInfo.SANs = append(tlsInfo.SANs, name)
	}

	tlsInfo.IsSelfSigned = isSelfSigned(cert)
	tlsInfo.IsExpired = cert.NotAfter.Before(time.Now())
	tlsInfo.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)

	return tlsInfo
}

// identifyFramework 识别 Web 框架
func (m *ServiceProbe) identifyFramework(headers http.Header, body string) string {
	bodyLower := strings.ToLower(body)

	if _, ok := headers["X-Aspnet-Version"]; ok || strings.Contains(bodyLower, "__viewstate") {
		return "ASP.NET"
	}
	if _, ok := headers["X-Spring-Boot"]; ok || strings.Contains(bodyLower, "spring-boot") {
		return "Spring Boot"
	}
	if _, ok := headers["X-Express"]; ok || strings.Contains(bodyLower, "express") {
		return "Express"
	}
	if _, ok := headers["X-Django"]; ok || strings.Contains(bodyLower, "django") {
		return "Django"
	}
	if _, ok := headers["X-Laravel-Session"]; ok || strings.Contains(bodyLower, "laravel") {
		return "Laravel"
	}
	if _, ok := headers["X-Flask"]; ok || strings.Contains(bodyLower, "flask") {
		return "Flask"
	}
	if _, ok := headers["X-Rails"]; ok || strings.Contains(bodyLower, "rails") {
		return "Ruby on Rails"
	}
	if _, ok := headers["X-AspNetMvc"]; ok {
		return "ASP.NET MVC"
	}
	return ""
}

// identifyCMS 识别 CMS
func (m *ServiceProbe) identifyCMS(body string) string {
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wp-includes") {
		return "WordPress"
	}
	if strings.Contains(bodyLower, "drupal") || strings.Contains(bodyLower, "sites/default") {
		return "Drupal"
	}
	if strings.Contains(bodyLower, "joomla") || strings.Contains(bodyLower, "media/jui") {
		return "Joomla"
	}
	if strings.Contains(bodyLower, "magento") {
		return "Magento"
	}
	if strings.Contains(bodyLower, "shopify") {
		return "Shopify"
	}
	return ""
}

// identifyLanguage 识别编程语言
func (m *ServiceProbe) identifyLanguage(headers http.Header, body string) string {
	if _, ok := headers["X-Powered-By"]; ok {
		poweredBy := strings.ToLower(headers.Get("X-Powered-By"))
		if strings.Contains(poweredBy, "php") {
			return "PHP"
		}
		if strings.Contains(poweredBy, "asp.net") {
			return "ASP.NET"
		}
		if strings.Contains(poweredBy, "express") {
			return "Node.js"
		}
		if strings.Contains(poweredBy, "django") {
			return "Python"
		}
	}
	return ""
}

// extractTitle 提取 HTML 标题
func extractTitle(body string) string {
	start := strings.Index(strings.ToLower(body), "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(strings.ToLower(body[start:]), "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

// isSelfSigned 判断是否为自签名证书
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Issuer.CommonName == cert.Subject.CommonName ||
		(len(cert.Issuer.Organization) > 0 && len(cert.Subject.Organization) > 0 &&
			cert.Issuer.Organization[0] == cert.Subject.Organization[0])
}

// isHTTPService 判断是否为 HTTP 服务
func isHTTPService(service string) bool {
	svcLower := strings.ToLower(service)
	return svcLower == "http" || svcLower == "https" ||
		strings.HasPrefix(svcLower, "http-") || svcLower == "http-proxy" || svcLower == "http-alt"
}

// fallbackPortMapWithResult 端口映射兜底（返回 ProbeResult）
func (m *ServiceProbe) fallbackPortMapWithResult(target *core.Target) *ProbeResult {
	if svc := m.store.LookupPort(target.Port); svc != "" {
		return &ProbeResult{Service: svc, Method: "port_map", Confidence: 40}
	}
	return nil
}
