package icmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vulnscan-backend/scan/core"
)

type PingScanner struct{}

func New() *PingScanner { return &PingScanner{} }

func (m *PingScanner) ID() string       { return "icmp_ping" }
func (m *PingScanner) Name() string     { return "ICMP 存活探测" }
func (m *PingScanner) Category() string { return "discover" }

var probePorts = []string{
	"80", "443", "22", "3389",
	"8080", "8443", "21", "25",
	"3306", "5432", "6379",
	"9200", "27017",
	"445", "135", "139",
	"53", "8888", "9090",
}

func (m *PingScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	timeout := parseTimeout(config)
	retries := parseRetries(config)
	concurrency := parseConcurrency(config)
	batchSize := parseBatchSize(config)

	if concurrency > len(targets) {
		concurrency = len(targets)
	}
	if concurrency < 1 {
		concurrency = 1
	}

	dnsCache := &dnsResolver{cache: make(map[string]string)}
	for _, t := range targets {
		h := t.Host
		if t.IP != "" {
			h = t.IP
		}
		if h != "" {
			dnsCache.resolve(h)
		}
	}

	aliveSet := &safeStringSet{m: make(map[string]struct{})}

	batches := splitTargets(targets, batchSize)
	for bi, batch := range batches {
		select {
		case <-ctx.Done():
			break
		default:
		}

		ips := make([]string, 0, len(batch))
		ipToTarget := make(map[string]*core.Target, len(batch))
		for _, t := range batch {
			h := t.Host
			if t.IP != "" {
				h = t.IP
			}
			ip := dnsCache.resolve(h)
			if ip == "" {
				continue
			}
			if _, exists := ipToTarget[ip]; !exists {
				ips = append(ips, ip)
				ipToTarget[ip] = t
			}
		}

		if len(ips) == 0 {
			continue
		}

		localIPs, remoteIPs := classifyByNetwork(ips)
		if len(localIPs) > 0 {
			alive := batchARPPing(ctx, localIPs, timeout, concurrency)
			for _, ip := range alive {
				aliveSet.add(ip)
			}
		}

		var icmpTargets []string
		for _, ip := range remoteIPs {
			if !aliveSet.has(ip) {
				icmpTargets = append(icmpTargets, ip)
			}
		}
		for _, ip := range localIPs {
			if !aliveSet.has(ip) {
				icmpTargets = append(icmpTargets, ip)
			}
		}

		if len(icmpTargets) > 0 {
			for attempt := 0; attempt <= retries; attempt++ {
				alive := batchICMPPing(ctx, icmpTargets, timeout)
				for _, ip := range alive {
					aliveSet.add(ip)
				}
				var remaining []string
				for _, ip := range icmpTargets {
					if !aliveSet.has(ip) {
						remaining = append(remaining, ip)
					}
				}
				icmpTargets = remaining
				if len(icmpTargets) == 0 {
					break
				}
			}
		}

		var tcpTargets []string
		for _, ip := range ips {
			if !aliveSet.has(ip) {
				tcpTargets = append(tcpTargets, ip)
			}
		}
		if len(tcpTargets) > 0 {
			alive := batchTCPPing(ctx, tcpTargets, timeout, concurrency)
			for _, ip := range alive {
				aliveSet.add(ip)
			}
		}

		slog.Debug("[*] ICMP批次完成",
			"batch", bi+1,
			"total_batches", len(batches),
			"batch_size", len(batch),
			"alive_so_far", aliveSet.len(),
		)
	}

	var mu sync.Mutex
	var aliveCount atomic.Int64
	for _, t := range targets {
		h := t.Host
		if t.IP != "" {
			h = t.IP
		}
		ip := dnsCache.resolve(h)
		if ip == "" || !aliveSet.has(ip) {
			continue
		}
		aliveCount.Add(1)
		aliveTarget := &core.Target{
			Host:     t.Host,
			IP:       ip,
			Port:     t.Port,
			Protocol: t.Protocol,
			URL:      t.URL,
			Extra:    t.Extra,
		}

		mu.Lock()
		result.Targets = append(result.Targets, aliveTarget)
		result.Findings = append(result.Findings, &core.Finding{
			ModuleID:   m.ID(),
			Target:     t,
			Type:       "host_alive",
			Title:      fmt.Sprintf("主机存活: %s", h),
			Severity:   "info",
			Confidence: 95,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"host": h,
				"ip":   ip,
			},
		})
		mu.Unlock()
	}

	result.Duration = time.Since(start)
	slog.Info("[+] ICMP存活探测完成",
		"targets", len(targets),
		"alive", aliveCount.Load(),
		"duration", result.Duration,
	)

	return result, nil
}

// --- 批量 ICMP: 一次性发包 + 异步收包 ---

func batchICMPPing(ctx context.Context, ips []string, timeout time.Duration) []string {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		slog.Debug("[*] 无法打开raw socket进行批量ICMP, 回退到逐个探测", "error", err)
		return fallbackICMPPing(ctx, ips, timeout)
	}
	defer conn.Close()

	icmpID := uint16(rand.Intn(65535))
	sent := make(map[string]struct{}, len(ips))

	for i, ip := range ips {
		select {
		case <-ctx.Done():
			break
		default:
		}
		dst := net.ParseIP(ip)
		if dst == nil {
			continue
		}
		msg := buildICMPEchoRequest(icmpID, uint16(i))
		_, _ = conn.WriteTo(msg, &net.IPAddr{IP: dst})
		sent[ip] = struct{}{}
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	var alive []string
	buf := make([]byte, 1500)
	remaining := len(sent)

	for remaining > 0 {
		select {
		case <-ctx.Done():
			return alive
		default:
		}

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if n < 8 {
			continue
		}

		if buf[0] == 0 {
			respID := binary.BigEndian.Uint16(buf[4:6])
			if respID == icmpID {
				srcIP := addr.String()
				if _, ok := sent[srcIP]; ok {
					alive = append(alive, srcIP)
					delete(sent, srcIP)
					remaining--
				}
			}
		}
	}

	return alive
}

func fallbackICMPPing(ctx context.Context, ips []string, timeout time.Duration) []string {
	var mu sync.Mutex
	var alive []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for i, ip := range ips {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string, seq uint16) {
			defer wg.Done()
			defer func() { <-sem }()
			if icmpPingOne(target, timeout, seq) {
				mu.Lock()
				alive = append(alive, target)
				mu.Unlock()
			}
		}(ip, uint16(i))
	}

	wg.Wait()
	return alive
}

func icmpPingOne(ip string, timeout time.Duration, seq uint16) bool {
	conn, err := net.DialTimeout("ip4:icmp", ip, timeout)
	if err != nil {
		slog.Debug("[*] ICMP dial 失败", "ip", ip, "error", err)
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	msg := buildICMPEchoRequest(12345, seq)
	if _, err := conn.Write(msg); err != nil {
		slog.Debug("[*] ICMP write 失败", "ip", ip, "error", err)
		return false
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		slog.Debug("[*] ICMP read 失败", "ip", ip, "error", err)
		return false
	}

	if n >= 4 && buf[0] == 0 {
		return true
	}
	if n >= 24 && buf[20] == 0 {
		return true
	}
	return false
}

// --- 批量 ARP Ping (局域网) ---

func batchARPPing(ctx context.Context, ips []string, timeout time.Duration, concurrency int) []string {
	var mu sync.Mutex
	var alive []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			if arpPing(target, timeout) {
				mu.Lock()
				alive = append(alive, target)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return alive
}

func arpPing(ip string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "0"), timeout)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		return true
	}
	return strings.Contains(err.Error(), "connection refused")
}

// --- 批量 TCP Ping: 端口并行 + 快速失败 ---

func batchTCPPing(ctx context.Context, ips []string, timeout time.Duration, concurrency int) []string {
	aliveSet := &safeStringSet{m: make(map[string]struct{})}
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	perPortTimeout := timeout / 3
	if perPortTimeout < 500*time.Millisecond {
		perPortTimeout = 500 * time.Millisecond
	}

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			if parallelTCPPing(ctx, target, perPortTimeout) {
				aliveSet.add(target)
			}
		}(ip)
	}

	wg.Wait()
	return aliveSet.list()
}

func parallelTCPPing(ctx context.Context, ip string, perPortTimeout time.Duration) bool {
	found := make(chan struct{}, 1)
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, port := range probePorts {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			select {
			case <-ctx2.Done():
				return
			default:
			}
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, p), perPortTimeout)
			if err == nil {
				conn.Close()
				select {
				case found <- struct{}{}:
					cancel()
				default:
				}
			}
		}(port)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-found:
		return true
	case <-done:
		return false
	case <-ctx.Done():
		return false
	}
}

// --- 网络分类 ---

var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil {
			privateRanges = append(privateRanges, network)
		}
	}
}

func isLocalNetwork(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, r := range privateRanges {
		if r.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func classifyByNetwork(ips []string) (local, remote []string) {
	for _, ip := range ips {
		if isLocalNetwork(ip) {
			local = append(local, ip)
		} else {
			remote = append(remote, ip)
		}
	}
	return
}

// --- DNS 解析缓存 ---

type dnsResolver struct {
	mu    sync.RWMutex
	cache map[string]string
}

func (r *dnsResolver) resolve(host string) string {
	r.mu.RLock()
	if ip, ok := r.cache[host]; ok {
		r.mu.RUnlock()
		return ip
	}
	r.mu.RUnlock()

	ip := doResolve(host)

	r.mu.Lock()
	r.cache[host] = ip
	r.mu.Unlock()

	return ip
}

func doResolve(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

// --- 线程安全 string set ---

type safeStringSet struct {
	mu sync.RWMutex
	m  map[string]struct{}
}

func (s *safeStringSet) add(v string) {
	s.mu.Lock()
	s.m[v] = struct{}{}
	s.mu.Unlock()
}

func (s *safeStringSet) has(v string) bool {
	s.mu.RLock()
	_, ok := s.m[v]
	s.mu.RUnlock()
	return ok
}

func (s *safeStringSet) len() int {
	s.mu.RLock()
	n := len(s.m)
	s.mu.RUnlock()
	return n
}

func (s *safeStringSet) list() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	return out
}

// --- ICMP 构建 ---

func buildICMPEchoRequest(id, seq uint16) []byte {
	msg := make([]byte, 8)
	msg[0] = 8 // Echo Request
	msg[1] = 0 // Code
	binary.BigEndian.PutUint16(msg[4:], id)
	binary.BigEndian.PutUint16(msg[6:], seq)
	chksum := icmpChecksum(msg)
	binary.BigEndian.PutUint16(msg[2:], chksum)
	return msg
}

func icmpChecksum(data []byte) uint16 {
	length := len(data)
	var sum uint32
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}

// --- 配置解析 ---

func parseTimeout(config map[string]interface{}) time.Duration {
	if config != nil {
		if v, ok := config["timeout"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
	}
	return 3 * time.Second
}

func parseRetries(config map[string]interface{}) int {
	if config != nil {
		if v, ok := config["retries"]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
	}
	return 1
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

func parseBatchSize(config map[string]interface{}) int {
	if config != nil {
		if v, ok := config["batch_size"]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
	}
	return 256
}

// --- 工具 ---

func splitTargets(targets []*core.Target, batchSize int) [][]*core.Target {
	if batchSize <= 0 {
		batchSize = 256
	}
	var batches [][]*core.Target
	for i := 0; i < len(targets); i += batchSize {
		end := i + batchSize
		if end > len(targets) {
			end = len(targets)
		}
		batches = append(batches, targets[i:end])
	}
	return batches
}
