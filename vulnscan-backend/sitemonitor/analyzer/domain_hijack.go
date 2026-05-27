package analyzer

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
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

	type dnsResult struct {
		name  string
		ips   []string
		cname string
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	dnsResults := make([]dnsResult, 0, len(resolvers))

	for name, resolver := range resolvers {
		wg.Add(1)
		go func(n, addr string) {
			defer wg.Done()
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 5 * time.Second}
					return d.DialContext(ctx, "udp", addr)
				},
			}
			dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			addrs, err := r.LookupHost(dnsCtx, host)
			if err != nil || len(addrs) == 0 {
				return
			}

			cname, _ := r.LookupCNAME(dnsCtx, host)

			mu.Lock()
			dnsResults = append(dnsResults, dnsResult{name: n, ips: addrs, cname: cname})
			mu.Unlock()
		}(name, resolver)
	}
	wg.Wait()

	if len(dnsResults) < 2 {
		return output, nil
	}

	hijackCfg := a.loadHijackConfig()

	var refIPs []string
	for _, dr := range dnsResults {
		if refIPs == nil {
			refIPs = dr.ips
			continue
		}
		if !hasOverlap(refIPs, dr.ips) {
			output.HasIssue = true
			output.Severity = "critical"
			resolverNames := make([]string, 0, len(dnsResults))
			resolverIPs := make(map[string][]string)
			for _, r := range dnsResults {
				resolverNames = append(resolverNames, r.name)
				resolverIPs[r.name] = r.ips
			}
			detailJSON, _ := json.Marshal(map[string]any{
				"reason":    "多 DNS 解析器结果无交集，存在 DNS 劫持嫌疑",
				"resolvers": resolverNames,
				"results":   resolverIPs,
			})
			output.DetailsJSON = string(detailJSON)
			return output, nil
		}
	}

	for _, dr := range dnsResults {
		for _, ip := range dr.ips {
			if hijackCfg.parkingIPs[ip] {
				output.HasIssue = true
				output.Severity = "critical"
				detailJSON, _ := json.Marshal(map[string]any{
					"reason":   "解析到已知的 Parking/Sinkhole IP",
					"ip":       ip,
					"resolver": dr.name,
				})
				output.DetailsJSON = string(detailJSON)
				return output, nil
			}
		}

		if dr.cname != "" && dr.cname != host+"." {
			lowerCname := strings.ToLower(dr.cname)
			for _, suspicious := range hijackCfg.suspiciousCNAMEs {
				if strings.Contains(lowerCname, suspicious) {
					output.HasIssue = true
					output.Severity = "high"
					detailJSON, _ := json.Marshal(map[string]any{
						"reason":   "CNAME 指向可疑域名",
						"cname":    dr.cname,
						"pattern":  suspicious,
						"resolver": dr.name,
					})
					output.DetailsJSON = string(detailJSON)
					return output, nil
				}
			}
		}
	}

	if snap != nil && snap.StatusCode > 0 && snap.Title != "" {
		for _, ht := range hijackCfg.hijackTitles {
			if strings.Contains(strings.ToLower(snap.Title), strings.ToLower(ht)) {
				output.HasIssue = true
				output.Severity = "high"
				detailJSON, _ := json.Marshal(map[string]any{
					"reason":  "页面标题匹配劫持特征",
					"title":   snap.Title,
					"pattern": ht,
				})
				output.DetailsJSON = string(detailJSON)
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

type hijackConfig struct {
	parkingIPs       map[string]bool
	hijackTitles     []string
	suspiciousCNAMEs []string
}

func (a *DomainHijackAnalyzer) loadHijackConfig() hijackConfig {
	cfg := hijackConfig{
		parkingIPs: make(map[string]bool),
	}
	if a.rules == nil {
		return cfg
	}
	data, err := a.rules.GetModuleRules("domain_hijack")
	if err != nil || len(data) == 0 {
		return cfg
	}

	var raw struct {
		ParkingIPs []struct {
			IP string `json:"ip"`
		} `json:"parking_ips"`
		HijackPatterns []struct {
			Pattern string `json:"pattern"`
			Name    string `json:"name"`
		} `json:"hijack_patterns"`
		SuspiciousCNAMEs []struct {
			Domain string `json:"domain"`
		} `json:"suspicious_cnames"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return cfg
	}

	for _, p := range raw.ParkingIPs {
		if p.IP != "" {
			cfg.parkingIPs[p.IP] = true
		}
	}
	for _, p := range raw.HijackPatterns {
		if p.Name != "" {
			cfg.hijackTitles = append(cfg.hijackTitles, p.Name)
		}
	}
	for _, c := range raw.SuspiciousCNAMEs {
		if c.Domain != "" {
			cfg.suspiciousCNAMEs = append(cfg.suspiciousCNAMEs, c.Domain)
		}
	}
	return cfg
}
