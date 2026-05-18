package serviceprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/scan/core"
)

type ServiceProbe struct {
	store *FingerprintStore
}

func New() *ServiceProbe {
	return &ServiceProbe{store: NewFingerprintStore(nil)}
}

func NewWithDB(db *gorm.DB) *ServiceProbe {
	return &ServiceProbe{store: NewFingerprintStore(db)}
}

func (m *ServiceProbe) ID() string       { return "service_probe" }
func (m *ServiceProbe) Name() string     { return "服务探测" }
func (m *ServiceProbe) Category() string { return "discover" }

func (m *ServiceProbe) Store() *FingerprintStore { return m.store }

func (m *ServiceProbe) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	concurrency := parseConcurrency(config)
	baseTimeout := parseTimeout(config)
	enableTLS := parseBool(config, "tls_fallback", true)
	sem := make(chan struct{}, concurrency)

	var probed atomic.Int64

	for _, t := range targets {
		if t.Port <= 0 {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target *core.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			probed.Add(1)
			timeout := m.adaptiveTimeout(target, baseTimeout)
			probeResult := m.probeWithChain(ctx, target, timeout, enableTLS)
			if probeResult == nil || probeResult.Service == "" {
				return
			}

			enriched := &core.Target{
				Host:     target.Host,
				IP:       target.IP,
				Port:     target.Port,
				Protocol: probeResult.Service,
				URL:      target.URL,
			}
			svcLower := strings.ToLower(probeResult.Service)
			isHTTP := svcLower == "http" || svcLower == "https" ||
				strings.HasPrefix(svcLower, "http-") || svcLower == "http-proxy" || svcLower == "http-alt"
			if isHTTP {
				scheme := "http"
				if strings.Contains(svcLower, "https") || target.Port == 443 || target.Port == 8443 {
					scheme = "https"
				}
				host := target.IP
				if target.Host != "" {
					host = target.Host
				}
				enriched.Protocol = scheme
				enriched.URL = fmt.Sprintf("%s://%s:%d", scheme, host, target.Port)
			}

			data := map[string]string{
				"service": probeResult.Service,
				"version": probeResult.Version,
				"banner":  probeResult.Banner,
				"method":  probeResult.Method,
			}

			if probeResult.HTTPInfo != nil {
				if probeResult.HTTPInfo.Title != "" {
					data["http_title"] = probeResult.HTTPInfo.Title
				}
				if probeResult.HTTPInfo.Server != "" {
					data["http_server"] = probeResult.HTTPInfo.Server
				}
				if probeResult.HTTPInfo.XPoweredBy != "" {
					data["x_powered_by"] = probeResult.HTTPInfo.XPoweredBy
				}
				if probeResult.HTTPInfo.Framework != "" {
					data["framework"] = probeResult.HTTPInfo.Framework
				}
				if probeResult.HTTPInfo.CMS != "" {
					data["cms"] = probeResult.HTTPInfo.CMS
				}
				if probeResult.HTTPInfo.Language != "" {
					data["language"] = probeResult.HTTPInfo.Language
				}
			}

			if probeResult.TLSInfo != nil {
				if probeResult.TLSInfo.CN != "" {
					data["tls_cn"] = probeResult.TLSInfo.CN
				}
				if len(probeResult.TLSInfo.SANs) > 0 {
					data["tls_sans"] = strings.Join(probeResult.TLSInfo.SANs, ",")
				}
				if len(probeResult.TLSInfo.Organization) > 0 {
					data["tls_org"] = strings.Join(probeResult.TLSInfo.Organization, ",")
				}
				data["tls_self_signed"] = fmt.Sprintf("%v", probeResult.TLSInfo.IsSelfSigned)
				data["tls_expired"] = fmt.Sprintf("%v", probeResult.TLSInfo.IsExpired)
				data["tls_days_until_expiry"] = fmt.Sprintf("%d", probeResult.TLSInfo.DaysUntilExpiry)
				if !probeResult.TLSInfo.NotAfter.IsZero() {
					data["tls_not_after"] = probeResult.TLSInfo.NotAfter.Format(time.RFC3339)
				}
			}

			title := fmt.Sprintf("检测到服务: %s", probeResult.Service)
			if probeResult.HTTPInfo != nil && probeResult.HTTPInfo.Title != "" {
				title = fmt.Sprintf("检测到服务: %s - %s", probeResult.Service, probeResult.HTTPInfo.Title)
			}

			mu.Lock()
			result.Findings = append(result.Findings, &core.Finding{
				ModuleID:   m.ID(),
				Target:     enriched,
				Type:       "service",
				Title:      title,
				Severity:   "info",
				Confidence: probeResult.Confidence,
				Evidence:   probeResult.Banner,
				Timestamp:  time.Now(),
				Data:       data,
			})
			result.Targets = append(result.Targets, enriched)
			mu.Unlock()
		}(t)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] 服务探测完成",
		"targets", len(targets),
		"probed", probed.Load(),
		"findings", len(result.Findings),
		"concurrency", concurrency,
		"duration", result.Duration,
	)

	return result, nil
}

type serviceMatch struct {
	Service    string
	Version    string
	Banner     string
	Method     string
	Confidence int
}

// isActiveOnlyPort: these ports never send a banner on connect — must send data first
func isActiveOnlyPort(port int) bool {
	switch port {
	case 6379, 11211, 2181, 1080, 502, 102, 47808, 4840, 9600,
		5432, 1883, 8883, 9042, 7687, 5632, 10050, 10051, 4222:
		return true
	default:
		return false
	}
}

func (m *ServiceProbe) adaptiveTimeout(target *core.Target, base time.Duration) time.Duration {
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}
	addr := net.JoinHostPort(host, strconv.Itoa(target.Port))

	rttStart := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	rtt := time.Since(rttStart)
	if err != nil {
		return base
	}
	conn.Close()

	adaptive := rtt*3 + 500*time.Millisecond
	if adaptive < 1*time.Second {
		adaptive = 1 * time.Second
	}
	if adaptive > base {
		adaptive = base
	}
	return adaptive
}

func (m *ServiceProbe) probeFast(ctx context.Context, target *core.Target, timeout time.Duration, enableTLS bool) *serviceMatch {
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}
	addr := net.JoinHostPort(host, strconv.Itoa(target.Port))

	probes := m.store.GetProbes(target.Port)

	if isActiveOnlyPort(target.Port) {
		return m.probeActiveOnly(ctx, target, addr, timeout, probes)
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return m.fallbackPortMap(target)
	}

	bannerTimeout := timeout
	if len(probes) > 0 {
		bannerTimeout = timeout / 3
		if bannerTimeout < 800*time.Millisecond {
			bannerTimeout = 800 * time.Millisecond
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(bannerTimeout))

	reader := bufio.NewReaderSize(conn, 4096)
	banner := readBanner(reader)

	if banner != "" {
		service, version, matched := m.store.MatchBanner(banner, target.Port)
		if matched {
			conn.Close()
			return &serviceMatch{
				Service: service, Version: version,
				Banner: truncate(banner, 512), Method: "banner_passive", Confidence: 85,
			}
		}
	}

	if len(probes) > 0 && len(probes[0].ProbeData) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, werr := conn.Write(probes[0].ProbeData); werr == nil {
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
			resp := readBanner(bufio.NewReaderSize(conn, 4096))
			if resp != "" {
				if matched := m.matchProbeResponse(probes[0], resp, target.Port); matched != nil {
					conn.Close()
					return matched
				}
			}
		}
	}
	conn.Close()

	if len(probes) > 1 {
		if match := m.activeProbeRemaining(ctx, target, addr, timeout, probes[1:]); match != nil {
			return match
		}
	}

	if enableTLS && isTLSPort(target.Port) {
		if match := m.tlsProbe(ctx, addr, target, timeout); match != nil {
			return match
		}
	}

	if banner != "" {
		if svc := m.store.LookupPort(target.Port); svc != "" {
			return &serviceMatch{
				Service: svc, Banner: truncate(banner, 512),
				Method: "banner_port_map", Confidence: 50,
			}
		}
		return &serviceMatch{
			Service: "unknown", Banner: truncate(banner, 512),
			Method: "banner_unknown", Confidence: 20,
		}
	}

	return m.fallbackPortMap(target)
}

// probeActiveOnly: skip banner wait entirely — these ports require sending data first
func (m *ServiceProbe) probeActiveOnly(ctx context.Context, target *core.Target, addr string, timeout time.Duration, probes []*CompiledFingerprint) *serviceMatch {
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
			return m.fallbackPortMap(target)
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
			return match
		}
	}

	return m.fallbackPortMap(target)
}

func (m *ServiceProbe) matchProbeResponse(probe *CompiledFingerprint, response string, port int) *serviceMatch {
	if probe.MatchRegex != nil && probe.MatchRegex.MatchString(response) {
		version := ""
		if probe.VersionExpr != nil {
			if sub := probe.VersionExpr.FindStringSubmatch(response); len(sub) > 1 {
				version = sub[1]
			}
		} else if sub := probe.MatchRegex.FindStringSubmatch(response); len(sub) > 1 {
			version = sub[1]
		}
		return &serviceMatch{
			Service: probe.Service, Version: version,
			Banner: truncate(response, 512), Method: "active_probe:" + probe.Name, Confidence: 80,
		}
	}

	service, version, matched := m.store.MatchBanner(response, port)
	if matched {
		return &serviceMatch{
			Service: service, Version: version,
			Banner: truncate(response, 512), Method: "active_cross:" + probe.Name, Confidence: 75,
		}
	}
	return nil
}

func (m *ServiceProbe) activeProbeRemaining(ctx context.Context, target *core.Target, addr string, timeout time.Duration, probes []*CompiledFingerprint) *serviceMatch {
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
			return nil
		}

		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, werr := conn.Write(probe.ProbeData); werr != nil {
			conn.Close()
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		response := readBanner(bufio.NewReaderSize(conn, 4096))
		conn.Close()

		if response == "" {
			continue
		}

		if match := m.matchProbeResponse(probe, response, target.Port); match != nil {
			return match
		}
	}
	return nil
}

func (m *ServiceProbe) tlsProbe(ctx context.Context, addr string, target *core.Target, timeout time.Duration) *serviceMatch {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}

	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil
	}

	_, _ = tlsConn.Write([]byte("GET / HTTP/1.0\r\nHost: probe\r\n\r\n"))
	_ = tlsConn.SetReadDeadline(time.Now().Add(timeout))
	resp := readBanner(bufio.NewReaderSize(tlsConn, 4096))
	tlsConn.Close()

	if resp == "" {
		return nil
	}

	service, version, matched := m.store.MatchBanner(resp, target.Port)
	if matched {
		return &serviceMatch{
			Service: service, Version: version,
			Banner: truncate(resp, 512), Method: "tls_probe", Confidence: 82,
		}
	}

	return &serviceMatch{
		Service: "HTTPS", Banner: truncate(resp, 512),
		Method: "tls_fallback", Confidence: 60,
	}
}

func (m *ServiceProbe) fallbackPortMap(target *core.Target) *serviceMatch {
	if svc := m.store.LookupPort(target.Port); svc != "" {
		return &serviceMatch{Service: svc, Method: "port_map", Confidence: 40}
	}
	return nil
}

func isTLSPort(port int) bool {
	switch port {
	case 443, 465, 636, 993, 995, 8443, 9443, 5061, 7002, 8883:
		return true
	default:
		return false
	}
}

func readBanner(reader *bufio.Reader) string {
	buf := make([]byte, 4096)
	n, _ := reader.Read(buf)
	if n == 0 {
		return ""
	}
	return string(buf[:n])
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func parseTimeout(config map[string]interface{}) time.Duration {
	if config != nil {
		if v, ok := config["timeout"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
	}
	return 5 * time.Second
}

func parseConcurrency(config map[string]interface{}) int {
	if config != nil {
		if v, ok := config["concurrency"]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
	}
	return 200
}

func parseBool(config map[string]interface{}, key string, def bool) bool {
	if config == nil {
		return def
	}
	if v, ok := config[key].(bool); ok {
		return v
	}
	return def
}
