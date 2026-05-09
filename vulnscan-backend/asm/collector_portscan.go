package asm

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type PortScanCollector struct {
	ports    []int
	timeout  time.Duration
	maxConns int
}

func NewPortScanCollector(ports []int, timeout time.Duration, maxConns int) *PortScanCollector {
	if len(ports) == 0 {
		ports = defaultPorts()
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if maxConns <= 0 {
		maxConns = 100
	}
	return &PortScanCollector{
		ports:    ports,
		timeout:  timeout,
		maxConns: maxConns,
	}
}

func (c *PortScanCollector) Name() string { return "port-scan" }

func (c *PortScanCollector) Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error) {
	ips, err := resolveSeedIPs(ctx, seed)
	if err != nil || len(ips) == 0 {
		return nil, err
	}

	var mu sync.Mutex
	var assets []DiscoveredAsset
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.maxConns)

	for _, ip := range ips {
		for _, port := range c.ports {
			wg.Add(1)
			go func(targetIP string, targetPort int) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()

				if isPortOpen(ctx, targetIP, targetPort, c.timeout) {
					service := guessServiceByPort(targetPort)
					mu.Lock()
					assets = append(assets, DiscoveredAsset{
						Type:   "port",
						Value:  fmt.Sprintf("%s:%d", targetIP, targetPort),
						Source: "port-scan",
						Attributes: map[string]string{
							"ip":      targetIP,
							"port":    fmt.Sprintf("%d", targetPort),
							"service": service,
						},
						FirstSeen: time.Now(),
						LastSeen:  time.Now(),
						Status:    "active",
					})
					mu.Unlock()
				}
			}(ip, port)
		}
	}

	wg.Wait()

	sort.Slice(assets, func(i, j int) bool {
		return assets[i].Value < assets[j].Value
	})

	return assets, nil
}

func isPortOpen(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func guessServiceByPort(port int) string {
	services := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		9200:  "elasticsearch",
		9300:  "elasticsearch-transport",
		27017: "mongodb",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}

func defaultPorts() []int {
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

func resolveSeedIPs(ctx context.Context, seed Seed) ([]string, error) {
	switch seed.Type {
	case "ip":
		return []string{seed.Value}, nil
	case "domain":
		ips, err := net.DefaultResolver.LookupHost(ctx, seed.Value)
		if err != nil {
			return nil, fmt.Errorf("解析域名 %s 失败: %w", seed.Value, err)
		}
		return ips, nil
	case "cidr":
		return expandCIDR(seed.Value)
	default:
		return nil, nil
	}
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
