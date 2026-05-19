package assethost

import (
	"net"
	"net/url"
	"strings"
)

const subdomainDiscoveryNamePrefix = "发现子域名:"

// ExtractHost 从 URL / host:port 字符串提取主机名（小写）。
func ExtractHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(strings.ToLower(raw), prefix) {
			raw = raw[len(prefix):]
			break
		}
	}
	parts := strings.SplitN(raw, "/", 2)
	host := parts[0]
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		maybePort := host[idx+1:]
		if _, err := net.LookupPort("tcp", maybePort); err == nil {
			host = host[:idx]
		}
	}
	return strings.ToLower(strings.TrimSpace(host))
}

// HostFromSubdomainDiscoveryName 解析「发现子域名: xxx」资产名称中的 FQDN。
func HostFromSubdomainDiscoveryName(name string) string {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, subdomainDiscoveryNamePrefix) {
		return ""
	}
	return ExtractHost(strings.TrimSpace(strings.TrimPrefix(name, subdomainDiscoveryNamePrefix)))
}

// IsStrictSubdomainOf 判断 child 是否为 parent 的真子域（二者均为主机名，非 URL）。
func IsStrictSubdomainOf(child, parent string) bool {
	child = ExtractHost(child)
	parent = ExtractHost(parent)
	if child == "" || parent == "" || child == parent {
		return false
	}
	return strings.HasSuffix(child, "."+parent)
}

// PrimaryHost 返回资产上最具扫描/展示意义的域名主机（优先更长的 FQDN，避免根域覆盖子域）。
func PrimaryHost(address, urlRaw, domain, ipv4 string) string {
	var hosts []string
	for _, raw := range []string{address, urlRaw, domain} {
		if h := ExtractHost(raw); h != "" && net.ParseIP(h) == nil {
			hosts = append(hosts, h)
		}
	}
	best := ""
	for _, h := range hosts {
		if len(h) > len(best) {
			best = h
		}
	}
	if best != "" {
		return best
	}
	ip := strings.TrimSpace(ipv4)
	if ip != "" {
		return ip
	}
	return ExtractHost(address)
}

// ShouldApplyPTRDomain 是否允许用 PTR 结果填充空 domain（禁止用根域 PTR 覆盖已有更具体的子域线索）。
func ShouldApplyPTRDomain(address, urlRaw, domain, name, ptrDomain string) bool {
	ptrDomain = ExtractHost(ptrDomain)
	if ptrDomain == "" {
		return false
	}
	if strings.TrimSpace(domain) != "" {
		return false
	}
	primary := PrimaryHost(address, urlRaw, "", "")
	if primary == "" {
		primary = HostFromSubdomainDiscoveryName(name)
	}
	if primary == "" {
		return true
	}
	if primary == ptrDomain {
		return true
	}
	if IsStrictSubdomainOf(primary, ptrDomain) {
		return false
	}
	return true
}

// ParseHTTPURLHost 解析 URL 并返回 hostname（用于导入等场景）。
func ParseHTTPURLHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	return ExtractHost(raw)
}
