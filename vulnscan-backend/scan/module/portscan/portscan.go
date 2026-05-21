package portscan

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vulnscan-backend/scan/core"
)

type PortScanner struct{}

func New() *PortScanner { return &PortScanner{} }

func (m *PortScanner) ID() string       { return "port_scan" }
func (m *PortScanner) Name() string     { return "端口扫描" }
func (m *PortScanner) Category() string { return "discover" }

func (m *PortScanner) Params() []core.ModuleParam {
	return []core.ModuleParam{
		{
			Key:          "ports",
			Name:         "端口范围",
			Type:         "string",
			DefaultValue: "top100",
			Description:  "top100 / top1000 / full，或自定义：22,80,443,8000-8100",
		},
	}
}

func (m *PortScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()

	ports := parsePorts(config)
	baseTimeout := core.PortConnectTimeoutForScan(config, len(ports))
	concurrency := core.ParseProbeConcurrency(config, 3000)

	result := &core.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var scanned atomic.Int64

	ac := newAdaptiveController(concurrency, core.MinProbeConcurrencyForPorts(len(ports)))

	for _, target := range targets {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		ip := resolveHost(target)
		if ip == "" {
			continue
		}

		rtt := probeRTT(ip, baseTimeout)
		dynamicTimeout := core.AdjustPortTimeoutByRTT(rtt, baseTimeout)
		if rtt > 0 {
			slog.Debug("[*] 动态超时", "target", ip, "rtt", rtt, "timeout", dynamicTimeout)
		}

		var wg sync.WaitGroup
		for _, port := range ports {
			select {
			case <-ctx.Done():
				wg.Wait()
				result.Duration = time.Since(start)
				return result, ctx.Err()
			default:
			}

			ac.acquire()
			wg.Add(1)

			go func(t *core.Target, dstIP string, p int, to time.Duration) {
				defer wg.Done()
				defer ac.release()

				connStart := time.Now()
				addr := net.JoinHostPort(dstIP, strconv.Itoa(p))
				conn, err := net.DialTimeout("tcp", addr, to)
				elapsed := time.Since(connStart)
				scanned.Add(1)

				if err != nil {
					if elapsed >= to-50*time.Millisecond {
						ac.reportTimeout()
					}
					return
				}
				conn.Close()
				ac.reportSuccess(elapsed)

				newTarget := &core.Target{
					Host:     t.Host,
					IP:       dstIP,
					Port:     p,
					Protocol: "tcp",
				}

				finding := &core.Finding{
					ModuleID:         "port_scan",
					Target:           newTarget,
					Type:             "port_open",
					Title:            fmt.Sprintf("开放端口: %s:%d/tcp", dstIP, p),
					Severity:         "info",
					Confidence:       100,
					ConfidenceReason: "TCP CONNECT 三次握手成功，端口确认开放",
					Timestamp:        time.Now(),
					Data: map[string]string{
						"ip":       dstIP,
						"port":     strconv.Itoa(p),
						"protocol": "tcp",
					},
				}

				mu.Lock()
				result.Targets = append(result.Targets, newTarget)
				result.Findings = append(result.Findings, finding)
				mu.Unlock()

				slog.Debug("[+] 端口开放", "target", dstIP, "port", p)
			}(target, ip, port, dynamicTimeout)
		}

		wg.Wait()
	}

	result.Duration = time.Since(start)

	slog.Info("[+] 端口扫描完成",
		"targets", len(targets),
		"ports_scanned", scanned.Load(),
		"open_ports", len(result.Targets),
		"duration", result.Duration,
		"final_concurrency", ac.currentConcurrency(),
	)

	return result, nil
}

// --- 自适应并发控制器 ---

type adaptiveController struct {
	sem        chan struct{}
	maxConc    int
	minConc    int
	curConc    atomic.Int64
	timeouts   atomic.Int64
	successes  atomic.Int64
	totalRTT   atomic.Int64
	checkEvery int64
	mu         sync.Mutex
}

func newAdaptiveController(maxConcurrency, minConcurrency int) *adaptiveController {
	if maxConcurrency < 100 {
		maxConcurrency = 100
	}
	if minConcurrency < 100 {
		minConcurrency = 100
	}
	if minConcurrency > maxConcurrency {
		minConcurrency = maxConcurrency
	}
	ac := &adaptiveController{
		sem:        make(chan struct{}, maxConcurrency),
		maxConc:    maxConcurrency,
		minConc:    minConcurrency,
		checkEvery: 1000,
	}
	ac.curConc.Store(int64(maxConcurrency))
	for i := 0; i < maxConcurrency; i++ {
		ac.sem <- struct{}{}
	}
	return ac
}

func (ac *adaptiveController) acquire() {
	<-ac.sem
}

func (ac *adaptiveController) release() {
	total := ac.timeouts.Load() + ac.successes.Load()
	if total > 0 && total%ac.checkEvery == 0 {
		ac.adjust()
	}
	ac.sem <- struct{}{}
}

func (ac *adaptiveController) reportTimeout() {
	ac.timeouts.Add(1)
}

func (ac *adaptiveController) reportSuccess(rtt time.Duration) {
	ac.successes.Add(1)
	ac.totalRTT.Add(int64(rtt))
}

func (ac *adaptiveController) currentConcurrency() int64 {
	return ac.curConc.Load()
}

func (ac *adaptiveController) adjust() {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	timeouts := ac.timeouts.Load()
	successes := ac.successes.Load()
	total := timeouts + successes
	if total == 0 {
		return
	}

	timeoutRate := float64(timeouts) / float64(total)
	cur := int(ac.curConc.Load())

	switch {
	case timeoutRate > 0.3:
		newConc := int(math.Max(float64(cur/2), float64(ac.minConc)))
		ac.resizeSem(newConc)
		slog.Debug("[*] 自适应降速", "timeout_rate", timeoutRate, "concurrency", newConc)
	case timeoutRate < 0.05 && cur < ac.maxConc:
		newConc := int(math.Min(float64(cur*3/2), float64(ac.maxConc)))
		ac.resizeSem(newConc)
		slog.Debug("[*] 自适应提速", "timeout_rate", timeoutRate, "concurrency", newConc)
	}

	ac.timeouts.Store(0)
	ac.successes.Store(0)
}

func (ac *adaptiveController) resizeSem(newSize int) {
	oldSize := int(ac.curConc.Load())
	if newSize == oldSize {
		return
	}

	if newSize > oldSize {
		for i := 0; i < newSize-oldSize; i++ {
			select {
			case ac.sem <- struct{}{}:
			default:
			}
		}
	}

	ac.curConc.Store(int64(newSize))
}

// --- RTT 探测 ---

func probeRTT(ip string, maxTimeout time.Duration) time.Duration {
	probeTimeout := maxTimeout
	if probeTimeout > time.Second {
		probeTimeout = time.Second
	}

	probePorts := []string{"80", "443", "22", "3389"}
	for _, port := range probePorts {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), probeTimeout)
		rtt := time.Since(start)
		if err == nil {
			conn.Close()
			return rtt
		}
		errStr := err.Error()
		if strings.Contains(errStr, "refused") {
			return rtt
		}
	}
	return 0
}

func resolveHost(t *core.Target) string {
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

// --- 配置解析 ---

// ParsePortsPreset 解析端口配置字符串（预设名或自定义列表，如 22,80,443 或 8000-8100）。
func ParsePortsPreset(portsStr string) []int {
	portsStr = strings.TrimSpace(portsStr)
	if portsStr == "" {
		return top100Ports()
	}
	switch portsStr {
	case "top100":
		return top100Ports()
	case "top1000":
		return top1000Ports()
	case "full":
		return fullPorts()
	default:
		return parsePortRange(portsStr)
	}
}

func parsePorts(config map[string]interface{}) []int {
	if config == nil {
		return top100Ports()
	}

	if portsStr, ok := config["ports"].(string); ok {
		return ParsePortsPreset(portsStr)
	}

	return top100Ports()
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
		return top100Ports()
	}
	return ports
}

func fullPorts() []int {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	return ports
}

func top100Ports() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 81, 88, 110, 111,
		119, 135, 139, 143, 161, 389, 443, 445, 465, 512,
		513, 514, 515, 548, 554, 587, 631, 636, 873, 902,
		993, 995, 1025, 1080, 1099, 1433, 1434, 1521, 1723, 2049,
		2121, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 3690, 4000,
		4443, 4848, 5000, 5432, 5555, 5601, 5672, 5900, 5984, 6000,
		6379, 6443, 6666, 7001, 7002, 7070, 7077, 8000, 8008, 8009,
		8080, 8081, 8088, 8090, 8161, 8443, 8888, 8899, 9000, 9001,
		9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000,
		11211, 15672, 27017, 27018, 28017, 50000, 50030, 50070, 61616, 61617,
	}
}

func top1000Ports() []int {
	ports := top100Ports()
	extra := []int{
		20, 24, 26, 37, 49, 69, 79, 82, 83, 84, 85, 86, 87, 89, 90,
		99, 100, 106, 113, 123, 137, 138, 144, 146, 163, 179, 199,
		211, 222, 256, 259, 264, 280, 311, 340, 366, 406, 407, 416,
		417, 420, 427, 444, 464, 497, 500, 502, 503, 507, 593, 616,
		623, 625, 664, 683, 691, 700, 705, 711, 726, 749, 765, 783,
		787, 800, 801, 808, 843, 880, 888, 898, 900, 901, 903, 911,
		981, 987, 990, 999, 1000, 1001, 1010, 1023, 1024, 1026, 1027,
		1028, 1029, 1030, 1040, 1050, 1100, 1200, 1234, 1241, 1311,
		1352, 1400, 1443, 1500, 1503, 1533, 1583, 1600, 1641, 1687,
		1700, 1717, 1761, 1782, 1801, 1862, 1900, 1935, 1947, 1972,
		1999, 2000, 2001, 2002, 2003, 2005, 2010, 2020, 2030, 2048,
		2065, 2100, 2111, 2160, 2170, 2190, 2200, 2222, 2251, 2260,
		2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399,
		2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2607,
		2638, 2710, 2717, 2725, 2800, 2809, 2811, 2869, 2901, 2920,
		2967, 2998, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017,
	}
	ports = append(ports, extra...)
	return ports
}
