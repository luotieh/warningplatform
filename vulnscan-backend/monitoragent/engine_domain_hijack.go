package monitoragent

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"
)

type DomainHijackEngine struct {
	Rules RuleStore
}

func (e *DomainHijackEngine) Name() string { return "domain_hijack" }

func (e *DomainHijackEngine) Run(ctx context.Context, task *TaskMessage, snap *PageSnapshot) (map[string]any, error) {
	result := map[string]any{
		"url":      task.URL,
		"hijacked": false,
	}

	host := extractHost(task.URL)
	if host == "" || net.ParseIP(host) != nil {
		result["skipped"] = true
		result["reason"] = "IP address, skip DNS check"
		return result, nil
	}

	resolvers := e.loadDNSResolvers()
	if len(resolvers) == 0 {
		result["skipped"] = true
		result["reason"] = "no DNS resolvers configured"
		return result, nil
	}

	dnsResults := make(map[string][]string)
	for name, resolver := range resolvers {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", resolver)
			},
		}

		dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := r.LookupHost(dnsCtx, host)
		cancel()
		if err == nil && len(addrs) > 0 {
			dnsResults[name] = addrs
		}
	}

	result["dns_results"] = dnsResults

	if len(dnsResults) < 2 {
		result["warning"] = "insufficient DNS results for comparison"
		return result, nil
	}

	var refIPs []string
	for _, ips := range dnsResults {
		if refIPs == nil {
			refIPs = ips
			continue
		}
		if !hasOverlap(refIPs, ips) {
			result["hijacked"] = true
			result["reason"] = "DNS results from different resolvers have no overlap"
			break
		}
	}

	parkingIPs := e.loadParkingIPs()
	for _, ips := range dnsResults {
		for _, ip := range ips {
			if parkingIPs[ip] {
				result["hijacked"] = true
				result["parking_ip"] = ip
				result["reason"] = "resolved to known parking/sinkhole IP"
				break
			}
		}
	}

	if snap != nil && snap.StatusCode > 0 {
		result["http_status"] = snap.StatusCode
		if snap.Title != "" {
			hijackTitles := e.loadHijackPatterns()
			for _, ht := range hijackTitles {
				if strings.Contains(strings.ToLower(snap.Title), strings.ToLower(ht)) {
					result["hijacked"] = true
					result["reason"] = "suspicious page title: " + snap.Title
					break
				}
			}
		}
	}

	return result, nil
}

func hasOverlap(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, ip := range a {
		set[ip] = true
	}
	for _, ip := range b {
		if set[ip] {
			return true
		}
	}
	return false
}

func (e *DomainHijackEngine) loadDNSResolvers() map[string]string {
	if e.Rules == nil {
		return nil
	}
	data, err := e.Rules.GetModuleRules("common")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		PublicDNS []struct {
			IP   string `json:"ip"`
			Name string `json:"name"`
		} `json:"public_dns"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	resolvers := make(map[string]string, len(cfg.PublicDNS))
	for _, d := range cfg.PublicDNS {
		if d.IP != "" {
			resolvers[d.Name] = d.IP + ":53"
		}
	}
	return resolvers
}

func (e *DomainHijackEngine) loadParkingIPs() map[string]bool {
	if e.Rules == nil {
		return nil
	}
	data, err := e.Rules.GetModuleRules("domain_hijack")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		ParkingIPs []struct {
			IP string `json:"ip"`
		} `json:"parking_ips"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	m := make(map[string]bool, len(cfg.ParkingIPs))
	for _, p := range cfg.ParkingIPs {
		if p.IP != "" {
			m[p.IP] = true
		}
	}
	return m
}

func (e *DomainHijackEngine) loadHijackPatterns() []string {
	if e.Rules == nil {
		return nil
	}
	data, err := e.Rules.GetModuleRules("domain_hijack")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		HijackPatterns []struct {
			Pattern string `json:"pattern"`
			Name    string `json:"name"`
		} `json:"hijack_patterns"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	titles := make([]string, 0, len(cfg.HijackPatterns))
	for _, p := range cfg.HijackPatterns {
		if p.Name != "" {
			titles = append(titles, p.Name)
		}
	}
	return titles
}
