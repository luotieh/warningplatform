package company

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/engine"
)

type CompanyRecon struct {
	client *http.Client
}

func New() *CompanyRecon {
	return &CompanyRecon{
		client: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 5,
				DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			},
		},
	}
}

func (m *CompanyRecon) ID() string       { return "company_recon" }
func (m *CompanyRecon) Name() string     { return "企业资产发现" }
func (m *CompanyRecon) Category() string { return "recon" }

type CompanyAsset struct {
	Type       string
	Value      string
	Source     string
	Confidence int
	Extra      map[string]string
}

func (m *CompanyRecon) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}

	companyName := parseString(config, "company_name", "")
	if companyName == "" && len(targets) > 0 {
		companyName = targets[0].Host
	}
	if companyName == "" {
		return result, fmt.Errorf("company_name is required")
	}

	seedDomains := parseStringSlice(config, "seed_domains")

	slog.Info("[*] 企业资产发现启动", "company", companyName, "seeds", len(seedDomains))

	var mu sync.Mutex
	var wg sync.WaitGroup
	allAssets := make(map[string]*CompanyAsset)

	addAsset := func(a *CompanyAsset) {
		mu.Lock()
		key := a.Type + ":" + a.Value
		if existing, ok := allAssets[key]; ok {
			if a.Confidence > existing.Confidence {
				existing.Confidence = a.Confidence
			}
			existing.Source += "," + a.Source
		} else {
			allAssets[key] = a
		}
		mu.Unlock()
	}

	collectors := []struct {
		name string
		fn   func(ctx context.Context, company string, seeds []string) []*CompanyAsset
	}{
		{"CT Log", m.collectFromCTLog},
		{"ICP Beian", m.collectFromICP},
		{"WHOIS Reverse", m.collectFromWHOIS},
		{"Search Engine", m.collectFromSearchEngine},
		{"ASN Lookup", m.collectFromASN},
	}

	for _, c := range collectors {
		wg.Add(1)
		go func(name string, fn func(ctx context.Context, company string, seeds []string) []*CompanyAsset) {
			defer wg.Done()
			assets := fn(ctx, companyName, seedDomains)
			for _, a := range assets {
				addAsset(a)
			}
			slog.Info("[+] 收集器完成", "collector", name, "found", len(assets))
		}(c.name, c.fn)
	}

	wg.Wait()

	for _, a := range allAssets {
		result.Findings = append(result.Findings, &engine.Finding{
			ModuleID:   m.ID(),
			Type:       a.Type,
			Title:      fmt.Sprintf("[%s] %s", a.Type, a.Value),
			Severity:   "info",
			Confidence: a.Confidence,
			Evidence:   fmt.Sprintf("source: %s", a.Source),
			Timestamp:  time.Now(),
			Data:       a.Extra,
		})
	}

	result.Duration = time.Since(start)
	slog.Info("[+] 企业资产发现完成",
		"company", companyName,
		"total_assets", len(allAssets),
		"duration", result.Duration,
	)

	return result, nil
}

// --- Collector: CT Log (crt.sh) ---

func (m *CompanyRecon) collectFromCTLog(ctx context.Context, company string, seeds []string) []*CompanyAsset {
	var results []*CompanyAsset

	orgAssets := m.queryCrtSh(ctx, fmt.Sprintf("%%organization=%s%%", url.QueryEscape(company)))
	results = append(results, orgAssets...)

	for _, domain := range seeds {
		domainAssets := m.queryCrtSh(ctx, fmt.Sprintf("%%.%s", domain))
		results = append(results, domainAssets...)
	}

	return results
}

func (m *CompanyRecon) queryCrtSh(ctx context.Context, query string) []*CompanyAsset {
	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}

	resp, err := m.client.Do(req)
	if err != nil {
		slog.Debug("crt.sh 请求失败", "error", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))

	var entries []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
		IssuerName string `json:"issuer_name"`
		OrgName    string `json:"organization_name"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var results []*CompanyAsset

	for _, e := range entries {
		names := strings.Split(e.NameValue, "\n")
		names = append(names, e.CommonName)

		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			name = strings.ToLower(name)
			if name == "" || strings.Contains(name, " ") || !strings.Contains(name, ".") {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}

			results = append(results, &CompanyAsset{
				Type:       "domain",
				Value:      name,
				Source:     "crt.sh",
				Confidence: 85,
				Extra: map[string]string{
					"org":    e.OrgName,
					"issuer": e.IssuerName,
				},
			})
		}
	}

	return results
}

// --- Collector: ICP 备案 ---

func (m *CompanyRecon) collectFromICP(ctx context.Context, company string, _ []string) []*CompanyAsset {
	apiURL := fmt.Sprintf("https://icp.chinaz.com/Home/PageData?query=%s&isMulti=false", url.QueryEscape(company))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Referer", "https://icp.chinaz.com/")

	resp, err := m.client.Do(req)
	if err != nil {
		slog.Debug("ICP查询失败", "error", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))

	domainRe := regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+`)
	matches := domainRe.FindAllString(string(body), -1)

	seen := make(map[string]struct{})
	var results []*CompanyAsset

	for _, domain := range matches {
		domain = strings.ToLower(domain)
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}

		if isLikelyDomain(domain) {
			results = append(results, &CompanyAsset{
				Type:       "domain",
				Value:      domain,
				Source:     "icp_beian",
				Confidence: 90,
				Extra:      map[string]string{"company": company},
			})
		}
	}

	return results
}

// --- Collector: WHOIS 反查 ---

func (m *CompanyRecon) collectFromWHOIS(ctx context.Context, company string, seeds []string) []*CompanyAsset {
	var results []*CompanyAsset

	for _, domain := range seeds {
		whoisInfo := m.queryWHOIS(ctx, domain)
		if whoisInfo == nil {
			continue
		}

		if email, ok := whoisInfo["registrant_email"]; ok && email != "" {
			results = append(results, &CompanyAsset{
				Type:       "email",
				Value:      email,
				Source:     "whois",
				Confidence: 80,
				Extra:      map[string]string{"domain": domain},
			})

			reverseResults := m.reverseWHOIS(ctx, email)
			results = append(results, reverseResults...)
		}

		if org, ok := whoisInfo["registrant_org"]; ok && org != "" {
			results = append(results, &CompanyAsset{
				Type:       "organization",
				Value:      org,
				Source:     "whois",
				Confidence: 75,
				Extra:      map[string]string{"domain": domain},
			})
		}
	}

	return results
}

func (m *CompanyRecon) queryWHOIS(ctx context.Context, domain string) map[string]string {
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", "whois.verisign-grs.com:43")
	if err != nil {
		return nil
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	_, err = fmt.Fprintf(conn, "domain %s\r\n", domain)
	if err != nil {
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(conn, 32*1024))
	if err != nil {
		return nil
	}

	result := make(map[string]string)
	body := string(data)

	patterns := map[string]*regexp.Regexp{
		"registrant_email": regexp.MustCompile(`(?i)Registrant\s+Email:\s*(.+)`),
		"registrant_org":   regexp.MustCompile(`(?i)Registrant\s+Organization:\s*(.+)`),
		"registrant_name":  regexp.MustCompile(`(?i)Registrant\s+Name:\s*(.+)`),
		"name_server":      regexp.MustCompile(`(?i)Name\s+Server:\s*(.+)`),
	}

	for key, re := range patterns {
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			result[key] = strings.TrimSpace(m[1])
		}
	}

	return result
}

func (m *CompanyRecon) reverseWHOIS(ctx context.Context, email string) []*CompanyAsset {
	apiURL := fmt.Sprintf("https://viewdns.info/reversewhois/?q=%s", url.QueryEscape(email))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))

	domainRe := regexp.MustCompile(`<td>([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+)</td>`)
	matches := domainRe.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]struct{})
	var results []*CompanyAsset

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		domain := strings.ToLower(m[1])
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}

		if isLikelyDomain(domain) {
			results = append(results, &CompanyAsset{
				Type:       "domain",
				Value:      domain,
				Source:     "reverse_whois",
				Confidence: 70,
				Extra:      map[string]string{"email": email},
			})
		}
	}

	return results
}

// --- Collector: 搜索引擎 Dorking ---

func (m *CompanyRecon) collectFromSearchEngine(ctx context.Context, company string, seeds []string) []*CompanyAsset {
	var results []*CompanyAsset

	queries := []string{
		fmt.Sprintf(`"%s" site:*.com`, company),
		fmt.Sprintf(`"%s" site:*.cn`, company),
		fmt.Sprintf(`"%s" site:*.net`, company),
	}
	for _, domain := range seeds {
		queries = append(queries, fmt.Sprintf(`site:%s`, domain))
	}

	for _, q := range queries {
		found := m.bingSearch(ctx, q)
		results = append(results, found...)
	}

	return results
}

func (m *CompanyRecon) bingSearch(ctx context.Context, query string) []*CompanyAsset {
	searchURL := fmt.Sprintf("https://www.bing.com/search?q=%s&count=50", url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))

	urlRe := regexp.MustCompile(`https?://([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})`)
	matches := urlRe.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]struct{})
	var results []*CompanyAsset

	skipDomains := map[string]struct{}{
		"bing.com": {}, "microsoft.com": {}, "google.com": {},
		"baidu.com": {}, "sogou.com": {}, "so.com": {},
		"w3.org": {}, "schema.org": {}, "googleapis.com": {},
	}

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		host := strings.ToLower(m[1])
		rootDomain := extractRootDomain(host)

		if _, skip := skipDomains[rootDomain]; skip {
			continue
		}
		if _, ok := seen[rootDomain]; ok {
			continue
		}
		seen[rootDomain] = struct{}{}

		if isLikelyDomain(rootDomain) {
			results = append(results, &CompanyAsset{
				Type:       "domain",
				Value:      rootDomain,
				Source:     "search_engine",
				Confidence: 50,
				Extra:      map[string]string{"query": extractQuery(m[0])},
			})
		}
	}

	return results
}

// --- Collector: ASN Lookup ---

func (m *CompanyRecon) collectFromASN(ctx context.Context, company string, seeds []string) []*CompanyAsset {
	var results []*CompanyAsset

	for _, domain := range seeds {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
		if err != nil || len(ips) == 0 {
			continue
		}

		ip := ips[0].IP.String()
		asnInfo := m.queryASN(ctx, ip)
		if asnInfo == nil {
			continue
		}

		if asn, ok := asnInfo["asn"]; ok {
			results = append(results, &CompanyAsset{
				Type:       "asn",
				Value:      asn,
				Source:     "asn_lookup",
				Confidence: 80,
				Extra:      asnInfo,
			})
		}

		if prefix, ok := asnInfo["prefix"]; ok && prefix != "" {
			results = append(results, &CompanyAsset{
				Type:       "ip_range",
				Value:      prefix,
				Source:     "asn_lookup",
				Confidence: 75,
				Extra:      asnInfo,
			})
		}
	}

	return results
}

func (m *CompanyRecon) queryASN(ctx context.Context, ip string) map[string]string {
	apiURL := fmt.Sprintf("https://ipinfo.io/%s/json", url.PathEscape(ip))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var info struct {
		IP     string `json:"ip"`
		Org    string `json:"org"`
		Region string `json:"region"`
		City   string `json:"city"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil
	}

	result := map[string]string{
		"ip":     info.IP,
		"org":    info.Org,
		"region": info.Region,
		"city":   info.City,
	}

	parts := strings.SplitN(info.Org, " ", 2)
	if len(parts) > 0 {
		result["asn"] = parts[0]
	}

	bgpURL := fmt.Sprintf("https://stat.ripe.net/data/network-info/data.json?resource=%s", url.QueryEscape(ip))
	bgpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, bgpURL, nil)
	if err != nil {
		return result
	}

	bgpResp, err := m.client.Do(bgpReq)
	if err != nil {
		return result
	}
	defer bgpResp.Body.Close()

	bgpBody, _ := io.ReadAll(io.LimitReader(bgpResp.Body, 64*1024))

	var bgpInfo struct {
		Data struct {
			Prefix string `json:"prefix"`
			ASNs   []int  `json:"asns"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bgpBody, &bgpInfo); err == nil {
		result["prefix"] = bgpInfo.Data.Prefix
	}

	return result
}

// --- Helpers ---

func isLikelyDomain(d string) bool {
	if len(d) < 4 || !strings.Contains(d, ".") {
		return false
	}
	parts := strings.Split(d, ".")
	tld := parts[len(parts)-1]
	validTLDs := map[string]struct{}{
		"com": {}, "cn": {}, "net": {}, "org": {}, "io": {},
		"cc": {}, "co": {}, "me": {}, "biz": {}, "info": {},
		"xyz": {}, "top": {}, "tech": {}, "club": {}, "online": {},
		"site": {}, "app": {}, "dev": {}, "cloud": {}, "ai": {},
		"edu": {}, "gov": {}, "mil": {},
		"com.cn": {}, "net.cn": {}, "org.cn": {},
	}
	_, ok := validTLDs[tld]
	return ok
}

func extractRootDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

func extractQuery(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return parsed.Host
}

func parseString(config map[string]interface{}, key, def string) string {
	if config != nil {
		if v, ok := config[key].(string); ok {
			return v
		}
	}
	return def
}

func parseStringSlice(config map[string]interface{}, key string) []string {
	if config == nil {
		return nil
	}
	v, ok := config[key]
	if !ok {
		return nil
	}

	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}
