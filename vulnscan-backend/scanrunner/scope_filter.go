package scanrunner

import (
	"log/slog"
	"net"
	"net/url"
	"strings"

	"code.yt-security.com/public/scanengine/core"
)

// ScopeFilter restricts scan results and target propagation to the original
// scan scope. It extracts registered root domains from the initial targets
// and rejects any finding/target whose host falls outside that set.
// CIDR targets are expanded into network ranges for proper IP containment checks.
type ScopeFilter struct {
	rootDomains map[string]struct{}
	rawIPs      map[string]struct{}
	cidrNets    []*net.IPNet
}

// NewScopeFilter builds a filter from the original task targets.
func NewScopeFilter(targets []string) *ScopeFilter {
	sf := &ScopeFilter{
		rootDomains: make(map[string]struct{}),
		rawIPs:      make(map[string]struct{}),
	}
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(t); err == nil {
			sf.cidrNets = append(sf.cidrNets, ipNet)
			continue
		}

		host := extractScopeHost(t)
		if host == "" {
			continue
		}
		if net.ParseIP(host) != nil {
			sf.rawIPs[host] = struct{}{}
			continue
		}
		rd := scopeRegisteredDomain(host)
		if rd != "" {
			sf.rootDomains[rd] = struct{}{}
		}
	}
	slog.Info("[ScopeFilter] 作用域已构建",
		"root_domains", mapKeys(sf.rootDomains),
		"raw_ips_count", len(sf.rawIPs),
		"cidr_nets", len(sf.cidrNets),
	)
	return sf
}

// InScope returns true if the host belongs to one of the original targets'
// registered domains, is one of the original IP addresses, or falls within
// any of the original CIDR ranges.
func (sf *ScopeFilter) InScope(host string) bool {
	if host == "" {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))

	if ip := net.ParseIP(host); ip != nil {
		if _, ok := sf.rawIPs[host]; ok {
			return true
		}
		for _, cidr := range sf.cidrNets {
			if cidr.Contains(ip) {
				return true
			}
		}
		return len(sf.rawIPs) == 0 && len(sf.cidrNets) == 0
	}

	rd := scopeRegisteredDomain(host)
	_, ok := sf.rootDomains[rd]
	return ok
}

// FilterTargets returns only in-scope targets.
func (sf *ScopeFilter) FilterTargets(targets []*core.Target) []*core.Target {
	if sf.isEmpty() {
		return targets
	}
	var result []*core.Target
	var filteredHosts []string
	for _, t := range targets {
		host := t.Host
		if host == "" {
			host = t.IP
		}
		if sf.InScope(host) {
			result = append(result, t)
		} else {
			if len(filteredHosts) < 10 {
				filteredHosts = append(filteredHosts, host)
			}
		}
	}
	filtered := len(targets) - len(result)
	if filtered > 0 {
		slog.Info("[ScopeFilter] 过滤外域目标",
			"filtered", filtered,
			"remaining", len(result),
			"sample_hosts", filteredHosts,
		)
	}
	return result
}

// FilterFindings returns only in-scope findings.
func (sf *ScopeFilter) FilterFindings(findings []*core.Finding) []*core.Finding {
	if sf.isEmpty() {
		return findings
	}
	var result []*core.Finding
	var filteredHosts []string
	for _, f := range findings {
		host := ""
		if f.Target != nil {
			host = f.Target.Host
			if host == "" {
				host = f.Target.IP
			}
			if host == "" && f.Target.URL != "" {
				host = extractScopeHost(f.Target.URL)
			}
		}
		if sf.InScope(host) {
			result = append(result, f)
		} else {
			if len(filteredHosts) < 10 {
				filteredHosts = append(filteredHosts, host)
			}
		}
	}
	filtered := len(findings) - len(result)
	if filtered > 0 {
		slog.Info("[ScopeFilter] 过滤外域发现",
			"filtered", filtered,
			"remaining", len(result),
			"sample_hosts", filteredHosts,
		)
	}
	return result
}

func (sf *ScopeFilter) isEmpty() bool {
	return len(sf.rootDomains) == 0 && len(sf.rawIPs) == 0 && len(sf.cidrNets) == 0
}

func extractScopeHost(rawTarget string) string {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return ""
	}
	if strings.Contains(rawTarget, "://") {
		u, err := url.Parse(rawTarget)
		if err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	if h, _, err := net.SplitHostPort(rawTarget); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(rawTarget)
}

var scopeTwoPartTLDs = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true,
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true,
	"com.au": true, "net.au": true, "org.au": true,
	"co.kr": true, "or.kr": true,
	"com.tw": true, "org.tw": true, "net.tw": true,
	"com.hk": true, "org.hk": true, "net.hk": true,
	"com.sg": true, "org.sg": true,
	"com.br": true, "org.br": true,
	"co.in": true, "org.in": true, "net.in": true,
	"com.ru": true, "org.ru": true,
	"co.nz": true, "org.nz": true,
	"com.mx": true, "org.mx": true,
}

func scopeRegisteredDomain(host string) string {
	host = strings.ToLower(host)
	parts := strings.Split(host, ".")
	n := len(parts)
	if n <= 2 {
		return host
	}
	if n >= 3 {
		lastTwo := parts[n-2] + "." + parts[n-1]
		if scopeTwoPartTLDs[lastTwo] {
			return strings.Join(parts[n-3:], ".")
		}
	}
	return strings.Join(parts[n-2:], ".")
}

func mapKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
