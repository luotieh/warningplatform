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
	"unicode"

	"vulnscan-backend/scan/core"
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
	Type             string
	Value            string
	Source           string
	Confidence       int
	ConfidenceReason string
	Extra            map[string]string
}

type reconContext struct {
	companyName     string
	explicitCompany bool
	seedDomains     []string
	seedRoots       []string
	companyTokens   []string
}

var (
	reverseWhoisDomainRe = regexp.MustCompile(`<td>([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+)</td>`)
	searchURLRe          = regexp.MustCompile(`https?://([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})`)
	secondLevelTLDs      = map[string]struct{}{
		"com.cn": {}, "net.cn": {}, "org.cn": {}, "gov.cn": {}, "edu.cn": {},
	}
	publicNoiseDomains = map[string]struct{}{
		"bing.com": {}, "microsoft.com": {}, "google.com": {}, "google.cn": {},
		"baidu.com": {}, "sogou.com": {}, "so.com": {}, "360.cn": {},
		"yahoo.com": {}, "yahoo.co.jp": {}, "yandex.ru": {}, "duckduckgo.com": {},
		"facebook.com": {}, "twitter.com": {}, "instagram.com": {}, "linkedin.com": {},
		"weibo.com": {}, "wechat.com": {}, "qq.com": {}, "douyin.com": {},
		"github.com": {}, "gitlab.com": {}, "stackoverflow.com": {}, "npmjs.com": {},
		"npmjs.org": {}, "jsdelivr.net": {}, "unpkg.com": {}, "cdnjs.com": {},
		"amazonaws.com": {}, "cloudflare.com": {}, "aliyun.com": {}, "tencentcloud.com": {},
		"huaweicloud.com": {}, "azure.com": {}, "digitalocean.com": {}, "herokuapp.com": {},
		"w3.org": {}, "schema.org": {}, "googleapis.com": {}, "gstatic.com": {},
		"csdn.net": {}, "oschina.net": {}, "segmentfault.com": {},
		"chinaz.com": {}, "admin5.com": {}, "aizhan.com": {}, "hostloc.com": {},
		"msn.com": {}, "live.com": {}, "outlook.com": {}, "hotmail.com": {},
	}
)

func (m *CompanyRecon) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}
	rc := buildReconContext(targets, config)

	if !rc.hasInputs() {
		result.Duration = time.Since(start)
		slog.Info("[company_recon] skip, missing company_name and seed_domains")
		return result, nil
	}

	slog.Info("[company_recon] start", "company", rc.companyName, "seeds", len(rc.seedDomains))

	var mu sync.Mutex
	var wg sync.WaitGroup
	allAssets := make(map[string]*CompanyAsset)

	addAsset := func(a *CompanyAsset) {
		if a == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()

		key := a.Type + ":" + a.Value
		if existing, ok := allAssets[key]; ok {
			newSource := !csvContains(existing.Source, a.Source)
			existing.Source = mergeCSV(existing.Source, a.Source)
			existing.Extra = mergeExtra(existing.Extra, a.Extra)
			if newSource {
				existing.Confidence = min(95, max(existing.Confidence, a.Confidence)+5)
			} else if a.Confidence > existing.Confidence {
				existing.Confidence = a.Confidence
			}
			existing.ConfidenceReason = mergeConfidenceReason(existing.ConfidenceReason, a.ConfidenceReason, existing.Source, existing.Confidence)
			if existing.Extra == nil {
				existing.Extra = map[string]string{}
			}
			existing.Extra["source"] = existing.Source
			existing.Extra["confidence_basis"] = existing.ConfidenceReason
			return
		}

		if a.Extra == nil {
			a.Extra = map[string]string{}
		}
		a.Extra["source"] = a.Source
		a.Extra["confidence_basis"] = a.ConfidenceReason
		allAssets[key] = a
	}

	collectors := []struct {
		name string
		fn   func(ctx context.Context, rc *reconContext) []*CompanyAsset
	}{
		{"CT Log", m.collectFromCTLog},
		{"ICP Beian", m.collectFromICP},
		{"WHOIS Reverse", m.collectFromWHOIS},
		{"Search Engine", m.collectFromSearchEngine},
		{"ASN Lookup", m.collectFromASN},
	}

	for _, collector := range collectors {
		wg.Add(1)
		go func(name string, fn func(ctx context.Context, rc *reconContext) []*CompanyAsset) {
			defer wg.Done()
			assets := fn(ctx, rc)
			for _, asset := range assets {
				addAsset(asset)
			}
			slog.Info("[company_recon] collector done", "collector", name, "found", len(assets))
		}(collector.name, collector.fn)
	}

	wg.Wait()

	for _, asset := range allAssets {
		data := map[string]string{
			"name":  asset.Value,
			"value": asset.Value,
			"type":  asset.Type,
		}
		for k, v := range asset.Extra {
			data[k] = v
		}

		target := &core.Target{Host: asset.Value}
		result.Findings = append(result.Findings, &core.Finding{
			ModuleID:          m.ID(),
			Target:            target,
			Type:              asset.Type,
			Title:             fmt.Sprintf("[%s] %s", asset.Type, asset.Value),
			Severity:          "info",
			Confidence:        asset.Confidence,
			ConfidenceReason:  asset.ConfidenceReason,
			Evidence:          fmt.Sprintf("source: %s", asset.Source),
			Timestamp:         time.Now(),
			Data:              data,
			VerificationLevel: core.VerifyPrinciple,
		})
	}

	result.Duration = time.Since(start)
	slog.Info("[company_recon] complete", "company", rc.companyName, "assets", len(allAssets), "duration", result.Duration)
	return result, nil
}

func (m *CompanyRecon) collectFromCTLog(ctx context.Context, rc *reconContext) []*CompanyAsset {
	var results []*CompanyAsset

	if rc.explicitCompany {
		results = append(results, m.queryCrtSh(ctx, fmt.Sprintf("%%organization=%s%%", url.QueryEscape(rc.companyName)), rc)...)
	}
	for _, domain := range rc.seedDomains {
		results = append(results, m.queryCrtSh(ctx, fmt.Sprintf("%%.%s", domain), rc)...)
	}
	return results
}

func (m *CompanyRecon) queryCrtSh(ctx context.Context, query string, rc *reconContext) []*CompanyAsset {
	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}

	resp, err := m.client.Do(req)
	if err != nil {
		slog.Debug("crt.sh request failed", "error", err)
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
	results := make([]*CompanyAsset, 0, len(entries))
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		names = append(names, entry.CommonName)
		for _, name := range names {
			domain := normalizeDomain(name)
			if domain == "" || strings.Contains(domain, " ") || !strings.Contains(domain, ".") {
				continue
			}
			if _, ok := seen[domain]; ok {
				continue
			}
			seen[domain] = struct{}{}

			asset := m.newDomainAsset(domain, "crt.sh", map[string]string{
				"org":    entry.OrgName,
				"issuer": entry.IssuerName,
				"query":  query,
			}, rc)
			if asset != nil {
				results = append(results, asset)
			}
		}
	}
	return results
}

func (m *CompanyRecon) collectFromICP(ctx context.Context, rc *reconContext) []*CompanyAsset {
	if !rc.explicitCompany {
		return nil
	}

	apiURL := fmt.Sprintf("https://icp.chinaz.com/Home/PageData?query=%s&isMulti=false", url.QueryEscape(rc.companyName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Referer", "https://icp.chinaz.com/")

	resp, err := m.client.Do(req)
	if err != nil {
		slog.Debug("ICP query failed", "error", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	var payload interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		// 非结构化返回大概率是 HTML/反爬页面，继续用正则会把导航域名扫进去。
		slog.Warn("[company_recon] ICP response is not structured JSON, skip")
		return nil
	}

	seen := make(map[string]struct{})
	results := []*CompanyAsset{}
	for _, domain := range extractDomainsFromJSON(payload) {
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}

		asset := m.newDomainAsset(domain, "icp_beian", map[string]string{
			"query_company": rc.companyName,
		}, rc)
		if asset != nil {
			results = append(results, asset)
		}
	}
	return results
}

func (m *CompanyRecon) collectFromWHOIS(ctx context.Context, rc *reconContext) []*CompanyAsset {
	results := []*CompanyAsset{}
	for _, domain := range rc.seedDomains {
		whoisInfo := m.queryWHOIS(ctx, domain)
		if whoisInfo == nil {
			continue
		}

		if email := strings.TrimSpace(whoisInfo["registrant_email"]); email != "" {
			results = append(results, &CompanyAsset{
				Type:             "email",
				Value:            email,
				Source:           "whois",
				Confidence:       80,
				ConfidenceReason: "基础分 80（WHOIS 注册邮箱直接提取） => 80%",
				Extra:            map[string]string{"domain": domain},
			})
			results = append(results, m.reverseWHOIS(ctx, email, rc)...)
		}

		if org := strings.TrimSpace(whoisInfo["registrant_org"]); org != "" {
			results = append(results, &CompanyAsset{
				Type:             "organization",
				Value:            org,
				Source:           "whois",
				Confidence:       75,
				ConfidenceReason: "基础分 75（WHOIS 注册组织字段直接提取） => 75%",
				Extra:            map[string]string{"domain": domain},
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

	if _, err := fmt.Fprintf(conn, "domain %s\r\n", domain); err != nil {
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(conn, 32*1024))
	if err != nil {
		return nil
	}

	body := string(data)
	result := make(map[string]string)
	patterns := map[string]*regexp.Regexp{
		"registrant_email": regexp.MustCompile(`(?i)Registrant\s+Email:\s*(.+)`),
		"registrant_org":   regexp.MustCompile(`(?i)Registrant\s+Organization:\s*(.+)`),
		"registrant_name":  regexp.MustCompile(`(?i)Registrant\s+Name:\s*(.+)`),
		"name_server":      regexp.MustCompile(`(?i)Name\s+Server:\s*(.+)`),
	}
	for key, re := range patterns {
		if match := re.FindStringSubmatch(body); len(match) > 1 {
			result[key] = strings.TrimSpace(match[1])
		}
	}
	return result
}

func (m *CompanyRecon) reverseWHOIS(ctx context.Context, email string, rc *reconContext) []*CompanyAsset {
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
	matches := reverseWhoisDomainRe.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]struct{})
	results := []*CompanyAsset{}
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		domain := normalizeDomain(match[1])
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}

		asset := m.newDomainAsset(domain, "reverse_whois", map[string]string{"email": email}, rc)
		if asset != nil {
			results = append(results, asset)
		}
	}
	return results
}

func (m *CompanyRecon) collectFromSearchEngine(ctx context.Context, rc *reconContext) []*CompanyAsset {
	if len(rc.seedDomains) == 0 {
		return nil
	}

	results := []*CompanyAsset{}
	for _, domain := range rc.seedDomains {
		query := fmt.Sprintf(`site:%s`, domain)
		results = append(results, m.bingSearch(ctx, query, rc)...)
	}
	return results
}

func (m *CompanyRecon) bingSearch(ctx context.Context, query string, rc *reconContext) []*CompanyAsset {
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
	matches := searchURLRe.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]struct{})
	results := []*CompanyAsset{}
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		host := normalizeDomain(match[1])
		rootDomain := extractRootDomain(host)
		if _, skip := publicNoiseDomains[rootDomain]; skip && !containsString(rc.seedRoots, rootDomain) {
			continue
		}
		if _, ok := seen[rootDomain]; ok {
			continue
		}
		seen[rootDomain] = struct{}{}

		asset := m.newDomainAsset(rootDomain, "search_engine", map[string]string{
			"query":        query,
			"matched_host": host,
		}, rc)
		if asset != nil {
			results = append(results, asset)
		}
	}
	return results
}

func (m *CompanyRecon) collectFromASN(ctx context.Context, rc *reconContext) []*CompanyAsset {
	results := []*CompanyAsset{}
	for _, domain := range rc.seedDomains {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
		if err != nil || len(ips) == 0 {
			continue
		}

		ip := ips[0].IP.String()
		asnInfo := m.queryASN(ctx, ip)
		if asnInfo == nil {
			continue
		}

		if asn := strings.TrimSpace(asnInfo["asn"]); asn != "" {
			results = append(results, &CompanyAsset{
				Type:             "asn",
				Value:            asn,
				Source:           "asn_lookup",
				Confidence:       80,
				ConfidenceReason: "基础分 80（种子域解析到 IP 后反查 ASN） => 80%",
				Extra:            asnInfo,
			})
		}
		if prefix := strings.TrimSpace(asnInfo["prefix"]); prefix != "" {
			results = append(results, &CompanyAsset{
				Type:             "ip_range",
				Value:            prefix,
				Source:           "asn_lookup",
				Confidence:       75,
				ConfidenceReason: "基础分 75（种子域解析到 IP 后反查 BGP 前缀） => 75%",
				Extra:            asnInfo,
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

func buildReconContext(targets []*core.Target, config map[string]interface{}) *reconContext {
	companyName := strings.TrimSpace(parseString(config, "company_name", ""))
	seedDomains := normalizeDomains(parseStringSlice(config, "seed_domains"))
	seedDomains = mergeStringSlices(seedDomains, extractSeedDomainsFromTargets(targets))

	seedRoots := make([]string, 0, len(seedDomains))
	for _, domain := range seedDomains {
		root := extractRootDomain(domain)
		if root != "" && !containsString(seedRoots, root) {
			seedRoots = append(seedRoots, root)
		}
	}

	return &reconContext{
		companyName:     companyName,
		explicitCompany: companyName != "",
		seedDomains:     seedDomains,
		seedRoots:       seedRoots,
		companyTokens:   tokenizeCompanyName(companyName),
	}
}

func (rc *reconContext) hasInputs() bool {
	return rc.explicitCompany || len(rc.seedDomains) > 0
}

func (m *CompanyRecon) newDomainAsset(domain, source string, extra map[string]string, rc *reconContext) *CompanyAsset {
	domain = normalizeDomain(domain)
	if !isLikelyDomain(domain) {
		return nil
	}
	if isNoiseDomain(domain, rc) {
		return nil
	}

	confidence, reason, keep, annotations := scoreDomainAsset(domain, source, extra, rc)
	if !keep {
		return nil
	}
	return &CompanyAsset{
		Type:             "domain",
		Value:            domain,
		Source:           source,
		Confidence:       confidence,
		ConfidenceReason: reason,
		Extra:            mergeExtra(extra, annotations),
	}
}

func scoreDomainAsset(domain, source string, extra map[string]string, rc *reconContext) (int, string, bool, map[string]string) {
	sourceLabel := map[string]string{
		"crt.sh":        "CT 日志证书记录",
		"icp_beian":     "ICP备案结果",
		"reverse_whois": "Reverse WHOIS 结果",
		"search_engine": "搜索引擎结果页提取",
	}[source]
	if sourceLabel == "" {
		sourceLabel = source
	}

	base := map[string]int{
		"crt.sh":        60,
		"icp_beian":     70,
		"reverse_whois": 45,
		"search_engine": 25,
	}[source]
	if base == 0 {
		base = 40
	}

	score := base
	reasonParts := []string{fmt.Sprintf("基础分 %d（%s）", base, sourceLabel)}
	annotations := map[string]string{}

	seedMatch := bestSeedMatch(domain, rc.seedDomains)
	companyMatch := domainContainsCompanyToken(domain, rc.companyTokens)
	metaCompanyMatch := metadataMatchesCompany(extra, rc.companyName)

	if seedMatch != "" {
		bonus := 15
		if normalizeDomain(seedMatch) == domain || extractRootDomain(seedMatch) == extractRootDomain(domain) {
			bonus = 20
		}
		score += bonus
		reasonParts = append(reasonParts, fmt.Sprintf("+%d（命中种子域 %s）", bonus, seedMatch))
		annotations["matched_seed"] = seedMatch
		annotations["matched_seed_root"] = extractRootDomain(seedMatch)
	}

	if metaCompanyMatch {
		score += 10
		reasonParts = append(reasonParts, "+10（返回元数据命中公司名）")
		annotations["matched_company"] = rc.companyName
	}

	if companyMatch {
		score += 5
		reasonParts = append(reasonParts, "+5（域名文本包含公司标识）")
	}

	switch source {
	case "icp_beian":
		if !rc.explicitCompany {
			return 0, "", false, nil
		}
		if len(rc.seedDomains) > 0 && seedMatch == "" && !metaCompanyMatch {
			return 0, "", false, nil
		}
	case "search_engine":
		if seedMatch == "" && !companyMatch {
			return 0, "", false, nil
		}
	case "reverse_whois":
		if seedMatch == "" && !companyMatch {
			return 0, "", false, nil
		}
	case "crt.sh":
		if (len(rc.seedDomains) > 0 || rc.explicitCompany) && seedMatch == "" && !metaCompanyMatch && !companyMatch {
			return 0, "", false, nil
		}
	}

	if score > 95 {
		score = 95
	}
	return score, fmt.Sprintf("%s => %d%%", strings.Join(reasonParts, " "), score), true, annotations
}

func isLikelyDomain(d string) bool {
	d = normalizeDomain(d)
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
	host = normalizeDomain(host)
	parts := strings.Split(host, ".")
	if len(parts) >= 3 {
		suffix := strings.Join(parts[len(parts)-2:], ".")
		if _, ok := secondLevelTLDs[suffix]; ok {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

func normalizeDomain(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimPrefix(raw, "*.")
	if strings.Contains(raw, "://") {
		if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
			raw = parsed.Hostname()
		}
	}
	if host, port, err := net.SplitHostPort(raw); err == nil && port != "" {
		raw = host
	}
	return strings.Trim(raw, ".")
}

func normalizeDomains(items []string) []string {
	seen := make(map[string]struct{})
	result := []string{}
	for _, item := range items {
		domain := normalizeDomain(item)
		if !isLikelyDomain(domain) {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	return result
}

func extractSeedDomainsFromTargets(targets []*core.Target) []string {
	seen := make(map[string]struct{})
	result := []string{}
	for _, target := range targets {
		for _, raw := range []string{target.Host, target.URL} {
			domain := normalizeDomain(raw)
			if !isLikelyDomain(domain) {
				continue
			}
			if _, ok := seen[domain]; ok {
				continue
			}
			seen[domain] = struct{}{}
			result = append(result, domain)
		}
	}
	return result
}

func tokenizeCompanyName(company string) []string {
	company = strings.ToLower(strings.TrimSpace(company))
	if company == "" {
		return nil
	}

	stopwords := map[string]struct{}{
		"co": {}, "com": {}, "cn": {}, "inc": {}, "ltd": {}, "llc": {},
		"group": {}, "corp": {}, "company": {}, "limited": {},
		"科技": {}, "网络": {}, "有限公司": {},
	}
	parts := strings.FieldsFunc(company, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("._-/()[]{}|,:;\"'`", r)
	})
	result := []string{}
	for _, part := range parts {
		if len([]rune(part)) < 2 {
			continue
		}
		if _, ok := stopwords[part]; ok {
			continue
		}
		result = append(result, part)
	}
	return result
}

func domainContainsCompanyToken(domain string, tokens []string) bool {
	for _, token := range tokens {
		if strings.Contains(strings.ToLower(domain), token) {
			return true
		}
	}
	return false
}

func metadataMatchesCompany(extra map[string]string, company string) bool {
	if company == "" || len(extra) == 0 {
		return false
	}
	companyKey := normalizeComparable(company)
	if companyKey == "" {
		return false
	}
	for _, key := range []string{"company", "org", "issuer"} {
		if value := extra[key]; value != "" && strings.Contains(normalizeComparable(value), companyKey) {
			return true
		}
	}
	return false
}

func normalizeComparable(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var builder strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func bestSeedMatch(domain string, seeds []string) string {
	domain = normalizeDomain(domain)
	root := extractRootDomain(domain)
	for _, seed := range seeds {
		seed = normalizeDomain(seed)
		if seed == domain || extractRootDomain(seed) == root {
			return seed
		}
	}
	return ""
}

func isNoiseDomain(domain string, rc *reconContext) bool {
	root := extractRootDomain(domain)
	if containsString(rc.seedRoots, root) {
		return false
	}
	_, noisy := publicNoiseDomains[root]
	return noisy
}

func mergeConfidenceReason(existing, incoming, sources string, score int) string {
	parts := []string{}
	for _, item := range []string{existing, incoming} {
		item = strings.TrimSpace(item)
		if item == "" || containsString(parts, item) {
			continue
		}
		parts = append(parts, item)
	}
	if strings.Contains(sources, ",") {
		cross := fmt.Sprintf("多来源交叉印证：%s => %d%%", sources, score)
		if !containsString(parts, cross) {
			parts = append(parts, cross)
		}
	}
	return strings.Join(parts, "；")
}

func mergeExtra(left, right map[string]string) map[string]string {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range left {
		out[k] = v
	}
	for k, v := range right {
		if strings.TrimSpace(v) != "" {
			out[k] = v
		}
	}
	return out
}

func mergeCSV(current, incoming string) string {
	items := []string{}
	for _, raw := range strings.Split(current+","+incoming, ",") {
		item := strings.TrimSpace(raw)
		if item == "" || containsString(items, item) {
			continue
		}
		items = append(items, item)
	}
	return strings.Join(items, ",")
}

func csvContains(csv, item string) bool {
	for _, current := range strings.Split(csv, ",") {
		if strings.TrimSpace(current) == strings.TrimSpace(item) {
			return true
		}
	}
	return false
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func mergeStringSlices(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	out := make([]string, 0, len(left)+len(right))
	for _, group := range [][]string{left, right} {
		for _, item := range group {
			if item == "" {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

func extractDomainsFromJSON(payload interface{}) []string {
	seen := make(map[string]struct{})
	results := []string{}

	var walk func(value interface{})
	walk = func(value interface{}) {
		switch current := value.(type) {
		case map[string]interface{}:
			for _, nested := range current {
				walk(nested)
			}
		case []interface{}:
			for _, nested := range current {
				walk(nested)
			}
		case string:
			for _, domain := range extractDomainsFromString(current) {
				if _, ok := seen[domain]; ok {
					continue
				}
				seen[domain] = struct{}{}
				results = append(results, domain)
			}
		}
	}
	walk(payload)
	return results
}

func extractDomainsFromString(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 256 {
		return nil
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<script") || strings.Contains(lower, "<a ") {
		return nil
	}

	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(",;|<>[](){}\"'", r)
	})
	if len(parts) == 0 {
		parts = []string{raw}
	}

	seen := make(map[string]struct{})
	results := []string{}
	for _, part := range parts {
		candidate := normalizeDomain(strings.Trim(part, "/"))
		if !isLikelyDomain(candidate) {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		results = append(results, candidate)
	}
	return results
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
	value, ok := config[key]
	if !ok {
		return nil
	}

	switch current := value.(type) {
	case []string:
		return current
	case []interface{}:
		result := []string{}
		for _, item := range current {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
