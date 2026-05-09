package nettopo

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/scan/engine"
)

type hopResult struct {
	TTL     int
	IP      string
	RTT     time.Duration
	Host    string
	Timeout bool
}

func (m *NetTopoScanner) traceroute(ctx context.Context, target *engine.Target, host string) []*engine.Finding {
	ip := target.IP
	if ip == "" {
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil
		}
		ip = ips[0]
	}

	maxHops := 30
	timeout := 2 * time.Second
	hops := make([]hopResult, 0, maxHops)
	consecutiveTimeouts := 0

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			break
		default:
		}

		hop := probeHop(ip, ttl, timeout)
		hops = append(hops, hop)

		if hop.Timeout {
			consecutiveTimeouts++
			if consecutiveTimeouts >= 5 {
				break
			}
		} else {
			consecutiveTimeouts = 0
			if hop.IP == ip {
				break
			}
		}
	}

	if len(hops) == 0 {
		return nil
	}

	var findings []*engine.Finding

	hopStrs := make([]string, 0, len(hops))
	var validHops int
	for _, h := range hops {
		if h.Timeout {
			hopStrs = append(hopStrs, fmt.Sprintf("%d:*", h.TTL))
		} else {
			validHops++
			hopStrs = append(hopStrs, fmt.Sprintf("%d:%s:%.1fms", h.TTL, h.IP, float64(h.RTT)/float64(time.Millisecond)))
		}
	}

	findings = append(findings, &engine.Finding{
		ModuleID:    "nettopo",
		Target:      target,
		Type:        "traceroute",
		Title:       fmt.Sprintf("路由追踪: %s → %s (%d跳)", host, ip, len(hops)),
		Description: fmt.Sprintf("经过 %d 跳到达目标，其中 %d 跳有响应", len(hops), validHops),
		Severity:    "info",
		Confidence:  85,
		Timestamp:   time.Now(),
		Data: map[string]string{
			"host":       host,
			"target_ip":  ip,
			"hops":       strings.Join(hopStrs, "|"),
			"hop_count":  fmt.Sprintf("%d", len(hops)),
			"valid_hops": fmt.Sprintf("%d", validHops),
		},
	})

	gateways := detectGateways(hops)
	if len(gateways) > 0 {
		findings = append(findings, &engine.Finding{
			ModuleID:    "nettopo",
			Target:      target,
			Type:        "network_gateway",
			Title:       fmt.Sprintf("网络网关: 发现 %d 个网关/边界节点", len(gateways)),
			Description: strings.Join(gateways, ", "),
			Severity:    "info",
			Confidence:  70,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"gateways": strings.Join(gateways, ","),
			},
		})
	}

	return findings
}

func probeHop(targetIP string, ttl int, timeout time.Duration) hopResult {
	conn, err := net.DialTimeout("ip4:icmp", targetIP, timeout)
	if err != nil {
		return probeHopUDP(targetIP, ttl, timeout)
	}
	conn.Close()
	return probeHopUDP(targetIP, ttl, timeout)
}

func probeHopUDP(host string, ttl int, timeout time.Duration) hopResult {
	hop := hopResult{TTL: ttl, Timeout: true}

	port := 33434 + ttl
	udpAddr := net.JoinHostPort(host, strconv.Itoa(port))

	start := time.Now()
	conn, err := net.DialTimeout("udp", udpAddr, timeout)
	if err != nil {
		return hop
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte{0x0})

	buf := make([]byte, 512)
	_, _ = conn.Read(buf)
	rtt := time.Since(start)

	remoteAddr := conn.RemoteAddr().(*net.UDPAddr)
	hopIP := remoteAddr.IP.String()

	if rtt < timeout {
		hop.IP = hopIP
		hop.RTT = rtt
		hop.Timeout = false
		names, _ := net.LookupAddr(hopIP)
		if len(names) > 0 {
			hop.Host = strings.TrimSuffix(names[0], ".")
		}
	}

	return hop
}

func detectGateways(hops []hopResult) []string {
	var gateways []string
	seen := make(map[string]bool)

	for _, h := range hops {
		if h.Timeout || h.IP == "" {
			continue
		}

		ip := net.ParseIP(h.IP)
		if ip == nil {
			continue
		}

		if isPrivateIP(ip) && !seen[h.IP] {
			seen[h.IP] = true
			label := h.IP
			if h.Host != "" {
				label = fmt.Sprintf("%s (%s)", h.IP, h.Host)
			}
			gateways = append(gateways, label)
		}
	}

	sort.Strings(gateways)
	return gateways
}

func isPrivateIP(ip net.IP) bool {
	private := []struct {
		network string
		mask    int
	}{
		{"10.0.0.0", 8},
		{"172.16.0.0", 12},
		{"192.168.0.0", 16},
	}

	for _, p := range private {
		_, cidr, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", p.network, p.mask))
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}
