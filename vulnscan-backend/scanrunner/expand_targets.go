package scanrunner

import (
	"fmt"
	"net"
	"strings"
)

const defaultMaxExpandedHosts = 4096

// ExpandScanTargets 将 IP、CIDR、域名等目标展开为扫描用的主机列表（CIDR 展开为单 IP，跳过网络/广播地址）。
func ExpandScanTargets(raw []string, maxHosts int) ([]string, error) {
	if maxHosts <= 0 {
		maxHosts = defaultMaxExpandedHosts
	}
	seen := make(map[string]struct{})
	var out []string

	for _, line := range raw {
		for _, part := range strings.FieldsFunc(line, func(r rune) bool {
			return r == '\n' || r == ',' || r == ';' || r == ' '
		}) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			expanded, err := expandOneTarget(part, maxHosts-len(out))
			if err != nil {
				return nil, err
			}
			for _, h := range expanded {
				key := strings.ToLower(h)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, h)
				if len(out) >= maxHosts {
					return nil, fmt.Errorf("展开后目标数超过上限 %d，请缩小网段或分批探测", maxHosts)
				}
			}
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("无有效扫描目标")
	}
	return out, nil
}

func expandOneTarget(t string, budget int) ([]string, error) {
	if budget <= 0 {
		return nil, fmt.Errorf("目标数量已达上限")
	}
	if strings.Contains(t, "://") {
		return []string{t}, nil
	}
	if ip := net.ParseIP(t); ip != nil {
		return []string{ip.String()}, nil
	}
	if _, ipNet, err := net.ParseCIDR(t); err == nil {
		return expandCIDRHosts(ipNet, budget)
	}
	if h, p, err := net.SplitHostPort(t); err == nil && h != "" {
		if ip := net.ParseIP(h); ip != nil {
			return []string{net.JoinHostPort(ip.String(), p)}, nil
		}
		return []string{t}, nil
	}
	return []string{t}, nil
}

func expandCIDRHosts(ipNet *net.IPNet, budget int) ([]string, error) {
	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		if len(ips) >= budget {
			return nil, fmt.Errorf("CIDR %s 展开主机数超过剩余配额 %d", ipNet.String(), budget)
		}
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	} else if len(ips) == 2 {
		ips = ips[:0]
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("CIDR %s 无可用主机地址", ipNet.String())
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
