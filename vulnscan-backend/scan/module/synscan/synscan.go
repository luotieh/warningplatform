package synscan

import (
	"context"
	"log/slog"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"vulnscan-backend/scan/engine"
)

type SYNScanner struct{}

func New() *SYNScanner { return &SYNScanner{} }

func (m *SYNScanner) ID() string       { return "syn_scan" }
func (m *SYNScanner) Name() string     { return "SYN 半开扫描" }
func (m *SYNScanner) Category() string { return "host" }

func (m *SYNScanner) Params() []engine.ModuleParam {
	return []engine.ModuleParam{
		{
			Key:          "ports",
			Name:         "端口范围",
			Type:         "select",
			DefaultValue: "top100",
			Description:  "扫描的端口范围，也可输入自定义范围如 80,443,1-1000",
			Options: []engine.ParamOption{
				{Value: "top100", Label: "常用100端口"},
				{Value: "top1000", Label: "常用1000端口"},
				{Value: "full", Label: "全端口 (1-65535)"},
			},
		},
		{
			Key:          "rate_limit",
			Name:         "发包速率",
			Type:         "number",
			DefaultValue: 10000,
			Description:  "SYN模式每秒发包数量",
			Min:          engine.PtrFloat(100),
			Max:          engine.PtrFloat(100000),
		},
	}
}

func (m *SYNScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}

	ports := parsePorts(config)
	timeout := parseTimeout(config)
	concurrency := parseConcurrency(config)
	rateLimit := parseRateLimit(config)

	if !canUseSYN() {
		slog.Warn("[!] SYN扫描需要root/管理员权限，回退到高速TCP Connect模式")
		return m.fastTCPConnect(ctx, targets, ports, timeout, concurrency), nil
	}

	return m.rawSYNScan(ctx, targets, ports, timeout, rateLimit, result, start), nil
}

// --- 真正的 raw socket SYN 扫描 ---

func (m *SYNScanner) rawSYNScan(ctx context.Context, targets []*engine.Target, ports []int, timeout time.Duration, rateLimit int, result *engine.ModuleResult, start time.Time) *engine.ModuleResult {
	localIP := getLocalIP()

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		slog.Error("[!] 无法打开raw socket", "error", err)
		return result
	}
	defer conn.Close()

	openPorts := &portResultSet{m: make(map[string]struct{})}

	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		m.receivePackets(ctx, conn, timeout, openPorts)
	}()

	var sentCount atomic.Int64
	ticker := time.NewTicker(time.Second / time.Duration(max(rateLimit, 1)))
	defer ticker.Stop()

	for _, t := range targets {
		ip := resolveIP(t)
		if ip == "" {
			continue
		}

		for _, port := range ports {
			select {
			case <-ctx.Done():
				goto waitRecv
			case <-ticker.C:
			}

			pkt := buildSYNPacket(localIP, ip, port)
			dst := &net.IPAddr{IP: net.ParseIP(ip)}
			_, _ = conn.WriteTo(pkt, dst)
			sentCount.Add(1)
		}
	}

waitRecv:
	slog.Info("[*] SYN发包完成，等待响应...",
		"sent", sentCount.Load(),
		"wait", timeout.String(),
	)

	select {
	case <-recvDone:
	case <-time.After(timeout + time.Second):
	case <-ctx.Done():
	}

	var mu sync.Mutex
	for _, t := range targets {
		ip := resolveIP(t)
		if ip == "" {
			continue
		}
		for _, port := range ports {
			key := net.JoinHostPort(ip, strconv.Itoa(port))
			if openPorts.has(key) {
				newTarget := &engine.Target{
					Host:     t.Host,
					IP:       ip,
					Port:     port,
					Protocol: "tcp",
				}
				mu.Lock()
				result.Targets = append(result.Targets, newTarget)
				mu.Unlock()
			}
		}
	}

	result.Duration = time.Since(start)
	slog.Info("[+] SYN扫描完成",
		"sent", sentCount.Load(),
		"open_ports", len(result.Targets),
		"duration", result.Duration,
	)

	return result
}

func (m *SYNScanner) receivePackets(ctx context.Context, conn net.PacketConn, timeout time.Duration, results *portResultSet) {
	deadline := time.Now().Add(timeout + 2*time.Second)
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 20 {
			continue
		}

		tcp := &layers.TCP{}
		err = tcp.DecodeFromBytes(buf[:n], gopacket.NilDecodeFeedback)
		if err != nil {
			continue
		}

		if tcp.SYN && tcp.ACK {
			srcIP := addr.String()
			key := net.JoinHostPort(srcIP, strconv.Itoa(int(tcp.SrcPort)))
			results.add(key)
		}
	}
}

func buildSYNPacket(srcIP, dstIP string, dstPort int) []byte {
	srcPort := 30000 + rand.Intn(30000)

	ip := layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Window:  65535,
		Seq:     rand.Uint32(),
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &tcp); err != nil {
		return nil
	}

	return buf.Bytes()
}

// --- 高速 TCP Connect 回退（非 root 场景）---

func (m *SYNScanner) fastTCPConnect(ctx context.Context, targets []*engine.Target, ports []int, timeout time.Duration, concurrency int) *engine.ModuleResult {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var scanned atomic.Int64

	sem := make(chan struct{}, concurrency)

	rttProbe := probeRTT(targets, timeout)
	if rttProbe > 0 && rttProbe*3 < timeout {
		timeout = rttProbe * 3
		slog.Info("[*] 动态超时调整", "rtt", rttProbe, "new_timeout", timeout)
	}

	for _, t := range targets {
		ip := resolveIP(t)
		if ip == "" {
			continue
		}

		for _, port := range ports {
			select {
			case <-ctx.Done():
				result.Duration = time.Since(start)
				return result
			default:
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(target *engine.Target, dstIP string, p int) {
				defer wg.Done()
				defer func() { <-sem }()

				scanned.Add(1)
				addr := net.JoinHostPort(dstIP, strconv.Itoa(p))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err != nil {
					return
				}
				conn.Close()

				newTarget := &engine.Target{
					Host:     target.Host,
					IP:       dstIP,
					Port:     p,
					Protocol: "tcp",
				}
				mu.Lock()
				result.Targets = append(result.Targets, newTarget)
				mu.Unlock()
			}(t, ip, port)
		}
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] 高速TCP Connect完成",
		"ports_scanned", scanned.Load(),
		"open_ports", len(result.Targets),
		"duration", result.Duration,
	)

	return result
}

func probeRTT(targets []*engine.Target, maxTimeout time.Duration) time.Duration {
	if len(targets) == 0 {
		return 0
	}

	t := targets[0]
	ip := resolveIP(t)
	if ip == "" {
		return 0
	}

	probeTimeout := maxTimeout
	if probeTimeout > 2*time.Second {
		probeTimeout = 2 * time.Second
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), probeTimeout)
	rtt := time.Since(start)
	if err != nil {
		conn2, err2 := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), probeTimeout)
		rtt = time.Since(start) / 2
		if err2 != nil {
			return 0
		}
		conn2.Close()
		return rtt
	}
	conn.Close()
	return rtt
}

// --- 工具 ---

type portResultSet struct {
	mu sync.RWMutex
	m  map[string]struct{}
}

func (s *portResultSet) add(key string) {
	s.mu.Lock()
	s.m[key] = struct{}{}
	s.mu.Unlock()
}

func (s *portResultSet) has(key string) bool {
	s.mu.RLock()
	_, ok := s.m[key]
	s.mu.RUnlock()
	return ok
}

func canUseSYN() bool {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "0.0.0.0"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "0.0.0.0"
}

func resolveIP(t *engine.Target) string {
	if t.IP != "" {
		return t.IP
	}
	if ip := net.ParseIP(t.Host); ip != nil {
		return t.Host
	}
	ips, err := net.LookupHost(t.Host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

func parsePorts(config map[string]interface{}) []int {
	if config != nil {
		if portsStr, ok := config["ports"].(string); ok {
			switch portsStr {
			case "top100":
				return defaultPorts()
			case "top1000":
				return top1000Ports()
			case "full":
				return fullPorts()
			default:
				return parsePortRange(portsStr)
			}
		}
	}
	return defaultPorts()
}

func fullPorts() []int {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	return ports
}

func top1000Ports() []int {
	ports := defaultPorts()
	extra := []int{
		20, 24, 26, 37, 49, 69, 79, 82, 83, 84, 85, 86, 87, 89, 90,
		99, 100, 106, 113, 123, 137, 138, 144, 146, 163, 179, 199,
		211, 222, 256, 259, 264, 280, 311, 340, 366, 406, 407, 416,
		417, 420, 427, 444, 464, 465, 497, 500, 502, 503, 507, 512,
		513, 514, 515, 524, 541, 548, 554, 587, 593, 616, 623, 625,
		631, 636, 664, 683, 691, 700, 705, 711, 726, 749, 765, 783,
		787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902,
		903, 911, 981, 987, 990, 999, 1000, 1001, 1010, 1023, 1024,
		1025, 1026, 1027, 1028, 1029, 1030, 1040, 1050, 1080, 1099,
		1100, 1200, 1234, 1241, 1311, 1352, 1400, 1434, 1443, 1500,
		1503, 1533, 1583, 1600, 1641, 1687, 1700, 1717, 1723, 1761,
		1782, 1801, 1862, 1900, 1935, 1947, 1972, 1999, 2000, 2001,
		2002, 2003, 2005, 2010, 2020, 2030, 2048, 2049, 2065, 2100,
		2111, 2121, 2160, 2170, 2181, 2190, 2200, 2222, 2251, 2260,
		2288, 2301, 2323, 2366, 2375, 2376, 2381, 2382, 2383, 2393,
		2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602,
		2604, 2607, 2638, 2710, 2717, 2725, 2800, 2809, 2811, 2869,
		2901, 2920, 2967, 2998, 3001, 3003, 3005, 3006, 3007, 3011,
	}
	ports = append(ports, extra...)
	return ports
}

func parsePortRange(s string) []int {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			low, _ := strconv.Atoi(strings.TrimSpace(bounds[0]))
			high, _ := strconv.Atoi(strings.TrimSpace(bounds[1]))
			for p := low; p <= high && p <= 65535; p++ {
				ports = append(ports, p)
			}
		} else {
			p, _ := strconv.Atoi(part)
			if p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return defaultPorts()
	}
	return ports
}

func defaultPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
		443, 445, 993, 995, 1433, 1521, 3306, 3389,
		5432, 5900, 6379, 8080, 8443, 9200, 27017,
	}
}

func parseTimeout(config map[string]interface{}) time.Duration {
	if config != nil {
		if v, ok := config["timeout"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
	}
	return 2 * time.Second
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
	return 3000
}

func parseRateLimit(config map[string]interface{}) int {
	if config != nil {
		if v, ok := config["rate_limit"]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
	}
	return 10000
}
