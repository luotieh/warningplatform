package udpscan

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vulnscan-backend/scan/core"
)

type UDPScanner struct{}

func New() *UDPScanner { return &UDPScanner{} }

func (m *UDPScanner) ID() string       { return "udp_scan" }
func (m *UDPScanner) Name() string     { return "UDP 端口扫描" }
func (m *UDPScanner) Category() string { return "host" }

func (m *UDPScanner) Params() []core.ModuleParam {
	return []core.ModuleParam{
		{
			Key:          "ports",
			Name:         "端口范围",
			Type:         "select",
			DefaultValue: "default",
			Description:  "扫描的UDP端口范围，也可输入自定义范围如 53,123,161",
			Options: []core.ParamOption{
				{Value: "default", Label: "常用UDP端口 (22个)"},
				{Value: "full", Label: "全端口 (1-65535)"},
			},
		},
	}
}

type udpProbe struct {
	Port    int
	Payload []byte
	Match   string
}

func (m *UDPScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var scanned atomic.Int64

	ports := parsePorts(config)
	timeout := parseTimeout(config)
	concurrency := parseConcurrency(config)

	sem := make(chan struct{}, concurrency)

	for _, t := range targets {
		host := t.Host
		if t.IP != "" {
			host = t.IP
		}
		if host == "" {
			continue
		}

		for _, port := range ports {
			select {
			case <-ctx.Done():
				result.Duration = time.Since(start)
				return result, ctx.Err()
			default:
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(target *core.Target, h string, p int) {
				defer wg.Done()
				defer func() { <-sem }()

				scanned.Add(1)
				probe := getProbe(p)
				if m.probeUDP(h, p, probe, timeout) {
					newTarget := &core.Target{
						Host:     target.Host,
						IP:       target.IP,
						Port:     p,
						Protocol: "udp",
					}
					mu.Lock()
					result.Targets = append(result.Targets, newTarget)
					result.Findings = append(result.Findings, &core.Finding{
						ModuleID:   m.ID(),
						Target:     target,
						Type:       "udp_port",
						Title:      serviceByPort(p),
						Severity:   "info",
						Confidence: 70,
						Timestamp:  time.Now(),
						Data: map[string]string{
							"port":     strconv.Itoa(p),
							"protocol": "udp",
							"service":  serviceByPort(p),
						},
					})
					mu.Unlock()
				}
			}(t, host, port)
		}
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] UDP扫描完成",
		"targets", len(targets),
		"ports_scanned", scanned.Load(),
		"open_ports", len(result.Targets),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *UDPScanner) probeUDP(host string, port int, probe *udpProbe, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	payload := probe.Payload
	if payload == nil {
		payload = []byte("\x00")
	}

	if _, err := conn.Write(payload); err != nil {
		return false
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	return n > 0
}

func getProbe(port int) *udpProbe {
	probes := map[int]*udpProbe{
		53:    {Port: 53, Payload: dnsQuery(), Match: "dns"},
		123:   {Port: 123, Payload: ntpQuery(), Match: "ntp"},
		161:   {Port: 161, Payload: snmpQuery(), Match: "snmp"},
		137:   {Port: 137, Payload: netbiosQuery(), Match: "netbios"},
		1900:  {Port: 1900, Payload: ssdpQuery(), Match: "ssdp"},
		5353:  {Port: 5353, Payload: mdnsQuery(), Match: "mdns"},
		3478:  {Port: 3478, Payload: stunQuery(), Match: "stun"},
		500:   {Port: 500, Payload: isakmpQuery(), Match: "ike"},
		514:   {Port: 514, Payload: syslogQuery(), Match: "syslog"},
		520:   {Port: 520, Payload: ripQuery(), Match: "rip"},
		623:   {Port: 623, Payload: ipmiQuery(), Match: "ipmi"},
		1194:  {Port: 1194, Payload: openvpnQuery(), Match: "openvpn"},
		67:    {Port: 67, Payload: dhcpQuery(), Match: "dhcp"},
		69:    {Port: 69, Payload: tftpQuery(), Match: "tftp"},
		5060:  {Port: 5060, Payload: sipQuery(), Match: "sip"},
		1434:  {Port: 1434, Payload: mssqlBrowserQuery(), Match: "mssql-browser"},
		11211: {Port: 11211, Payload: memcachedUDPQuery(), Match: "memcached"},
		5632:  {Port: 5632, Payload: pcanywhereQuery(), Match: "pcanywhere"},
		47808: {Port: 47808, Payload: bacnetQuery(), Match: "bacnet"},
		502:   {Port: 502, Payload: modbusUDPQuery(), Match: "modbus"},
		4500:  {Port: 4500, Payload: isakmpNatQuery(), Match: "ipsec-nat"},
		27960: {Port: 27960, Payload: quake3Query(), Match: "quake3"},
	}

	if p, ok := probes[port]; ok {
		return p
	}
	return &udpProbe{Port: port, Payload: []byte("\x00")}
}

// ============================================================
// UDP Protocol Payload Generators
// ============================================================

func dnsQuery() []byte {
	return []byte{
		0xAA, 0xAA, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x04, 'b', 'i', 'n', 'd',
		0x00, 0x00, 0x10, 0x00, 0x03,
	}
}

func ntpQuery() []byte {
	buf := make([]byte, 48)
	buf[0] = 0x1B
	return buf
}

func snmpQuery() []byte {
	return []byte{
		0x30, 0x26,
		0x02, 0x01, 0x01,
		0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
		0xa0, 0x19,
		0x02, 0x04, 0x71, 0xb4, 0xb5, 0x68,
		0x02, 0x01, 0x00,
		0x02, 0x01, 0x00,
		0x30, 0x0b, 0x30, 0x09,
		0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x05, 0x00,
	}
}

func netbiosQuery() []byte {
	return []byte{
		0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
		0x00, 0x01,
	}
}

func ssdpQuery() []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
}

func mdnsQuery() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00, 0x00, 0x0c, 0x00, 0x01,
	}
}

func stunQuery() []byte {
	return []byte{
		0x00, 0x01, 0x00, 0x00,
		0x21, 0x12, 0xa4, 0x42,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c,
	}
}

func isakmpQuery() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x10, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x1c,
	}
}

func isakmpNatQuery() []byte {
	buf := make([]byte, 32)
	buf[17] = 0x10
	buf[18] = 0x02
	buf[27] = 0x20
	return buf
}

func syslogQuery() []byte {
	return []byte("<14>1 - - - - - -\n")
}

func ripQuery() []byte {
	return []byte{
		0x01, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x10,
	}
}

func ipmiQuery() []byte {
	return []byte{
		0x06, 0x00, 0xff, 0x07,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x09,
		0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5,
	}
}

func openvpnQuery() []byte {
	return []byte{0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func dhcpQuery() []byte {
	buf := make([]byte, 300)
	buf[0] = 0x01
	buf[1] = 0x01
	buf[2] = 0x06
	buf[236] = 0x63
	buf[237] = 0x82
	buf[238] = 0x53
	buf[239] = 0x63
	buf[240] = 0x35
	buf[241] = 0x01
	buf[242] = 0x01
	buf[243] = 0xff
	return buf
}

func tftpQuery() []byte {
	return []byte{0x00, 0x01, 0x00, 0x00, 0x6e, 0x65, 0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00}
}

func sipQuery() []byte {
	return []byte("OPTIONS sip:probe SIP/2.0\r\nVia: SIP/2.0/UDP probe;branch=z9hG4bK-probe\r\nMax-Forwards: 0\r\nTo: <sip:probe>\r\nFrom: <sip:probe>;tag=probe\r\nCall-ID: probe@probe\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n")
}

func mssqlBrowserQuery() []byte {
	return []byte{0x02}
}

func memcachedUDPQuery() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		's', 't', 'a', 't', 's', '\r', '\n',
	}
}

func pcanywhereQuery() []byte {
	return []byte{0x00, 0x00, 0x00, 0x00}
}

func bacnetQuery() []byte {
	return []byte{
		0x81, 0x04, 0x00, 0x05,
		0x01,
	}
}

func modbusUDPQuery() []byte {
	return []byte{
		0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
		0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
	}
}

func quake3Query() []byte {
	return []byte{0xff, 0xff, 0xff, 0xff, 'g', 'e', 't', 's', 't', 'a', 't', 'u', 's', 0x0a}
}

// ============================================================
// Port → Service Name Mapping
// ============================================================

func serviceByPort(port int) string {
	m := map[int]string{
		53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
		123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 161: "SNMP",
		162: "SNMP-Trap", 500: "IKE", 502: "Modbus", 514: "Syslog",
		520: "RIP", 623: "IPMI",
		1194: "OpenVPN", 1434: "MSSQL-Browser",
		1900: "SSDP", 3478: "STUN",
		4500: "IPSec-NAT", 5060: "SIP", 5353: "mDNS",
		5632:  "pcAnywhere",
		11211: "Memcached",
		27960: "Quake3", 47808: "BACnet",
	}
	if s, ok := m[port]; ok {
		return s
	}
	return "Unknown-UDP"
}

func defaultUDPPorts() []int {
	return []int{
		53, 67, 69, 123, 137, 161, 162,
		500, 502, 514, 520, 623,
		1194, 1434, 1900,
		3478, 4500, 5060, 5353, 5632,
		11211, 47808,
	}
}

func parsePorts(config map[string]interface{}) []int {
	if config != nil {
		if portsStr, ok := config["ports"].(string); ok {
			switch portsStr {
			case "default":
				return defaultUDPPorts()
			case "full":
				return fullPorts()
			default:
				return parsePortRange(portsStr)
			}
		}
	}
	return defaultUDPPorts()
}

func fullPorts() []int {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
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
		return []int{53, 123, 161}
	}
	return ports
}

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
	return 100
}
