package analyzer

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"
)

type DomainHijackAnalyzer struct {
	rules RuleAccessor
}

func NewDomainHijackAnalyzer(rules RuleAccessor) *DomainHijackAnalyzer {
	return &DomainHijackAnalyzer{rules: rules}
}

func (a *DomainHijackAnalyzer) Dimension() string { return "domain_hijack" }

func (a *DomainHijackAnalyzer) Analyze(ctx context.Context, input *Input) (*Output, error) {
	snap, err := parseSnapshot(input.SnapshotJSON)
	if err != nil {
		return nil, err
	}

	output := &Output{HasIssue: false}

	host := extractHost(input.URL)
	if host == "" || net.ParseIP(host) != nil {
		return output, nil
	}

	resolvers := a.loadDNSResolvers()
	if len(resolvers) == 0 {
		return output, nil
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

	if len(dnsResults) < 2 {
		return output, nil
	}

	var refIPs []string
	for _, ips := range dnsResults {
		if refIPs == nil {
			refIPs = ips
			continue
		}
		if !hasOverlap(refIPs, ips) {
			output.HasIssue = true
			output.Severity = "critical"
			output.DetailsJSON = `{"reason":"dns results from different resolvers have no overlap"}`
			return output, nil
		}
	}

	parkingIPs := a.loadParkingIPs()
	for _, ips := range dnsResults {
		for _, ip := range ips {
			if parkingIPs[ip] {
				output.HasIssue = true
				output.Severity = "critical"
				output.DetailsJSON = `{"reason":"resolved to known parking/sinkhole IP","ip":"` + ip + `"}`
				return output, nil
			}
		}
	}

	if snap != nil && snap.StatusCode > 0 && snap.Title != "" {
		hijackTitles := a.loadHijackTitles()
		for _, ht := range hijackTitles {
			if strings.Contains(strings.ToLower(snap.Title), strings.ToLower(ht)) {
				output.HasIssue = true
				output.Severity = "high"
				output.DetailsJSON = `{"reason":"suspicious page title: ` + snap.Title + `"}`
				return output, nil
			}
		}
	}

	return output, nil
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

func (a *DomainHijackAnalyzer) loadDNSResolvers() map[string]string {
	if a.rules == nil {
		return nil
	}
	data, err := a.rules.GetModuleRules("common")
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

func (a *DomainHijackAnalyzer) loadParkingIPs() map[string]bool {
	if a.rules == nil {
		return nil
	}
	data, err := a.rules.GetModuleRules("domain_hijack")
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

func (a *DomainHijackAnalyzer) loadHijackTitles() []string {
	if a.rules == nil {
		return nil
	}
	data, err := a.rules.GetModuleRules("domain_hijack")
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
