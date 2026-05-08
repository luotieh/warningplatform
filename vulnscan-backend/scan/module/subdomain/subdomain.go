package subdomain

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vulnscan-backend/dict"
	"vulnscan-backend/scan/engine"
)

type SubdomainScanner struct {
	dictStore *dict.Store
}

func New(dictStore *dict.Store) *SubdomainScanner {
	if dictStore == nil {
		dictStore = dict.NewStore(nil)
	}
	return &SubdomainScanner{dictStore: dictStore}
}

func (m *SubdomainScanner) ID() string       { return "subdomain_brute" }
func (m *SubdomainScanner) Name() string     { return "子域名爆破" }
func (m *SubdomainScanner) Category() string { return "recon" }

type ScanStats struct {
	Queried   atomic.Int64
	Found     atomic.Int64
	Errors    atomic.Int64
	Passive   atomic.Int64
	StartTime time.Time
}

func (m *SubdomainScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}

	concurrency := parseInt(config, "concurrency", 300)
	timeout := parseDuration(config, "timeout", 3*time.Second)
	wordlist := m.getWordlist(config)
	enableRecursive := parseBool(config, "recursive", false)
	maxDepth := parseInt(config, "max_depth", 2)
	enablePassive := parseBool(config, "passive", true)
	enableCDN := parseBool(config, "cdn_detect", true)

	resolver := newCachedResolver(timeout, parseResolvers(config))
	stats := &ScanStats{StartTime: start}

	var mu sync.Mutex
	allResults := make(map[string]*subdomainResult)

	for _, t := range targets {
		domain := extractDomain(t)
		if domain == "" {
			continue
		}

		slog.Info("[*] 开始子域名扫描", "domain", domain, "wordlist", len(wordlist), "passive", enablePassive)

		wildcard := detectWildcardEnhanced(ctx, domain, resolver)
		if wildcard.isWildcard {
			slog.Warn("[!] 检测到泛解析", "domain", domain, "wildcard_ips", wildcard.ips)
		}

		rateCtrl := newRateController(concurrency)

		passiveCh := make(chan []*subdomainResult, 1)
		if enablePassive {
			go func() {
				passiveCh <- m.passiveCollect(ctx, domain, stats)
			}()
		} else {
			passiveCh <- nil
		}

		bruteResults := m.bruteForce(ctx, domain, wordlist, rateCtrl, resolver, wildcard, stats)

		if !wildcard.isWildcard && len(bruteResults) > len(wordlist)/2 {
			slog.Warn("[!] 子域名命中率异常高，可能是泛解析漏检", "domain", domain, "found", len(bruteResults), "wordlist_size", len(wordlist))
			wildcard = detectWildcardEnhanced(ctx, domain, resolver)
			if wildcard.isWildcard {
				slog.Warn("[!] 二次检测确认泛解析，重新过滤", "domain", domain, "wildcard_ips", wildcard.ips)
				var filtered []*subdomainResult
				for _, r := range bruteResults {
					if !isWildcardMatch(wildcard, r.ips) {
						filtered = append(filtered, r)
					}
				}
				slog.Info("[*] 泛解析过滤完成", "before", len(bruteResults), "after", len(filtered))
				bruteResults = filtered
			}
		}

		for _, r := range bruteResults {
			if _, ok := allResults[r.domain]; !ok {
				allResults[r.domain] = r
			}
		}

		passiveResults := <-passiveCh
		for _, r := range passiveResults {
			if _, ok := allResults[r.domain]; !ok {
				allResults[r.domain] = r
			}
		}
		if len(passiveResults) > 0 {
			slog.Info("[*] 被动收集完成", "domain", domain, "found", len(passiveResults))
		}

		if enableRecursive && len(bruteResults) > 0 {
			recursiveResults := m.recursiveBrute(ctx, bruteResults, wordlist, rateCtrl, resolver, wildcard, maxDepth, 1, stats)
			for _, r := range recursiveResults {
				if _, ok := allResults[r.domain]; !ok {
					allResults[r.domain] = r
				}
			}
		}

		m.batchEnrich(ctx, allResults, resolver)

		if enableCDN {
			for _, r := range allResults {
				r.cdn = detectCDN(r)
			}
		}

		ipGroups := aggregateByIP(allResults)

		for domain, r := range allResults {
			newTarget := &engine.Target{
				Host:     domain,
				IP:       r.ip,
				Protocol: "tcp",
			}

			finding := &engine.Finding{
				ModuleID:         m.ID(),
				Target:           newTarget,
				Type:             "subdomain",
				Title:            fmt.Sprintf("发现子域名: %s", domain),
				Severity:         "info",
				Confidence:       r.confidence,
				ConfidenceReason: fmt.Sprintf("来源: %s，DNS 解析验证", r.source),
				Timestamp:        time.Now(),
				Data: map[string]string{
					"domain": domain,
					"ip":     r.ip,
					"ips":    strings.Join(r.ips, ","),
					"cname":  r.cname,
					"source": r.source,
					"cdn":    r.cdn,
					"mx":     strings.Join(r.mx, ","),
					"ns":     strings.Join(r.ns, ","),
					"txt":    strings.Join(r.txt, ","),
				},
			}

			mu.Lock()
			result.Targets = append(result.Targets, newTarget)
			result.Findings = append(result.Findings, finding)
			mu.Unlock()
		}

		_ = ipGroups
	}

	result.Duration = time.Since(start)
	slog.Info("[+] 子域名扫描完成",
		"queries", stats.Queried.Load(),
		"passive", stats.Passive.Load(),
		"found", len(allResults),
		"errors", stats.Errors.Load(),
		"duration", result.Duration,
	)

	return result, nil
}

// --- 数据结构 ---

type subdomainResult struct {
	domain     string
	ip         string
	ips        []string
	cname      string
	source     string
	confidence int
	cdn        string
	mx         []string
	ns         []string
	txt        []string
}

// --- 被动收集 ---

func (m *SubdomainScanner) passiveCollect(ctx context.Context, domain string, stats *ScanStats) []*subdomainResult {
	type collectorFunc func(ctx context.Context, domain string) []*subdomainResult

	collectors := []struct {
		name string
		fn   collectorFunc
	}{
		{"crt.sh", collectFromCrtSh},
		{"dns_transfer", collectFromDNSTransfer},
		{"tls_cert", collectFromTLSCert},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var results []*subdomainResult
	seen := make(map[string]struct{})

	for _, c := range collectors {
		wg.Add(1)
		go func(name string, fn collectorFunc) {
			defer wg.Done()
			collected := fn(ctx, domain)
			mu.Lock()
			for _, r := range collected {
				if _, ok := seen[r.domain]; !ok {
					seen[r.domain] = struct{}{}
					r.source = name
					results = append(results, r)
					stats.Passive.Add(1)
				}
			}
			mu.Unlock()
			slog.Debug("[*] 被动收集", "source", name, "found", len(collected))
		}(c.name, c.fn)
	}

	wg.Wait()
	return results
}

func collectFromCrtSh(ctx context.Context, domain string) []*subdomainResult {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "VulnScan/2.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var results []*subdomainResult
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if name == "" || name == domain {
				continue
			}
			if !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			results = append(results, &subdomainResult{domain: name, confidence: 80})
		}
	}
	return results
}

func collectFromDNSTransfer(ctx context.Context, domain string) []*subdomainResult {
	nsRecords, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err != nil || len(nsRecords) == 0 {
		return nil
	}

	var results []*subdomainResult
	for _, ns := range nsRecords {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		conn, err := net.DialTimeout("tcp", nsHost+":53", 5*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
	}
	return results
}

func collectFromTLSCert(ctx context.Context, domain string) []*subdomainResult {
	commonPorts := []string{"443", "8443", "4443"}
	seen := make(map[string]struct{})
	var results []*subdomainResult

	for _, port := range commonPorts {
		dialer := &tls.Dialer{
			Config: &tls.Config{InsecureSkipVerify: true},
		}

		ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := dialer.DialContext(ctx2, "tcp", domain+":"+port)
		cancel()
		if err != nil {
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			continue
		}

		for _, cert := range tlsConn.ConnectionState().PeerCertificates {
			names := append(cert.DNSNames, cert.Subject.CommonName)
			for _, name := range names {
				name = strings.TrimPrefix(name, "*.")
				if name == "" || name == domain {
					continue
				}
				if !strings.HasSuffix(name, "."+domain) && name != domain {
					continue
				}
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = struct{}{}
				results = append(results, &subdomainResult{domain: name, confidence: 85})
			}
		}
		conn.Close()
	}
	return results
}

// --- 增强泛解析检测 ---

type wildcardInfo struct {
	isWildcard    bool
	ips           []string
	ttlConsistent bool
}

func detectWildcardEnhanced(ctx context.Context, domain string, resolver *cachedResolver) wildcardInfo {
	testPrefixes := []string{
		fmt.Sprintf("x%d-wc-test", rand.Intn(999999)),
		fmt.Sprintf("q%d-wc-chk", rand.Intn(999999)),
		fmt.Sprintf("z%d-wc-ver", rand.Intn(999999)),
		fmt.Sprintf("a%d-rndchk", rand.Intn(999999)),
		fmt.Sprintf("m%d-wildtst", rand.Intn(999999)),
	}

	var allIPs [][]string
	resolvedCount := 0
	for _, prefix := range testPrefixes {
		fqdn := prefix + "." + domain
		ips, _, err := resolver.resolve(ctx, fqdn)
		if err != nil || len(ips) == 0 {
			continue
		}
		allIPs = append(allIPs, ips)
		resolvedCount++
	}

	if resolvedCount < 3 {
		return wildcardInfo{isWildcard: false}
	}

	baseIPs := allIPs[0]
	sort.Strings(baseIPs)
	baseKey := strings.Join(baseIPs, ",")
	matchCount := 1
	for i := 1; i < len(allIPs); i++ {
		sort.Strings(allIPs[i])
		if strings.Join(allIPs[i], ",") == baseKey {
			matchCount++
		}
	}

	if matchCount < 3 {
		return wildcardInfo{isWildcard: false}
	}

	slog.Info("[*] 泛解析检测", "domain", domain, "tests", resolvedCount, "matches", matchCount, "wildcard_ips", baseIPs)

	return wildcardInfo{
		isWildcard:    true,
		ips:           baseIPs,
		ttlConsistent: true,
	}
}

func isWildcardMatch(wildcard wildcardInfo, ips []string) bool {
	if !wildcard.isWildcard {
		return false
	}
	for _, ip := range ips {
		for _, wip := range wildcard.ips {
			if ip == wip {
				return true
			}
		}
	}
	return false
}

// --- 自适应速率控制 ---

type rateController struct {
	sem         chan struct{}
	maxConc     int
	curConc     atomic.Int64
	errors      atomic.Int64
	successes   atomic.Int64
	checkPeriod int64
	mu          sync.Mutex
}

func newRateController(maxConcurrency int) *rateController {
	rc := &rateController{
		sem:         make(chan struct{}, maxConcurrency),
		maxConc:     maxConcurrency,
		checkPeriod: 500,
	}
	rc.curConc.Store(int64(maxConcurrency))
	for i := 0; i < maxConcurrency; i++ {
		rc.sem <- struct{}{}
	}
	return rc
}

func (rc *rateController) acquire() {
	<-rc.sem
}

func (rc *rateController) release(success bool) {
	if success {
		rc.successes.Add(1)
	} else {
		rc.errors.Add(1)
	}

	total := rc.errors.Load() + rc.successes.Load()
	if total > 0 && total%rc.checkPeriod == 0 {
		rc.adjust()
	}

	rc.sem <- struct{}{}
}

func (rc *rateController) adjust() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	errs := rc.errors.Load()
	succ := rc.successes.Load()
	total := errs + succ
	if total == 0 {
		return
	}

	errRate := float64(errs) / float64(total)
	cur := int(rc.curConc.Load())

	switch {
	case errRate > 0.4:
		newConc := cur / 2
		if newConc < 50 {
			newConc = 50
		}
		rc.resize(newConc)
		slog.Debug("[*] DNS降速", "error_rate", errRate, "concurrency", newConc)
	case errRate < 0.05 && cur < rc.maxConc:
		newConc := cur * 3 / 2
		if newConc > rc.maxConc {
			newConc = rc.maxConc
		}
		rc.resize(newConc)
	}

	rc.errors.Store(0)
	rc.successes.Store(0)
}

func (rc *rateController) resize(newSize int) {
	old := int(rc.curConc.Load())
	if newSize > old {
		for i := 0; i < newSize-old; i++ {
			select {
			case rc.sem <- struct{}{}:
			default:
			}
		}
	}
	rc.curConc.Store(int64(newSize))
}

// --- 爆破 ---

func (m *SubdomainScanner) bruteForce(ctx context.Context, baseDomain string, wordlist []string, rc *rateController, resolver *cachedResolver, wildcard wildcardInfo, stats *ScanStats) []*subdomainResult {
	domains := make([]string, len(wordlist))
	for i, word := range wordlist {
		domains[i] = word + "." + baseDomain
	}

	pipeline := NewPipelineDNS(nil, 5000, 3*time.Second)
	pipelineResults := pipeline.BulkResolve(domains)

	if pipelineResults != nil && len(pipelineResults) > 0 {
		return m.processPipelineResults(pipelineResults, wildcard, resolver, stats)
	}

	return m.bruteForceStandard(ctx, baseDomain, wordlist, rc, resolver, wildcard, stats)
}

func (m *SubdomainScanner) processPipelineResults(pipelineResults map[string]*dnsEntry, wildcard wildcardInfo, resolver *cachedResolver, stats *ScanStats) []*subdomainResult {
	var results []*subdomainResult

	for domain, entry := range pipelineResults {
		stats.Queried.Add(1)
		if entry.err != nil || len(entry.ips) == 0 {
			continue
		}

		if isWildcardMatch(wildcard, entry.ips) {
			continue
		}

		confidence := 90
		if entry.cname != "" {
			confidence = 95
		}

		results = append(results, &subdomainResult{
			domain:     domain,
			ip:         entry.ips[0],
			ips:        entry.ips,
			cname:      entry.cname,
			source:     "brute_pipeline",
			confidence: confidence,
		})
		stats.Found.Add(1)
	}

	return results
}

func (m *SubdomainScanner) bruteForceStandard(ctx context.Context, baseDomain string, wordlist []string, rc *rateController, resolver *cachedResolver, wildcard wildcardInfo, stats *ScanStats) []*subdomainResult {
	var mu sync.Mutex
	var results []*subdomainResult
	seen := make(map[string]struct{})
	var wg sync.WaitGroup

	for _, word := range wordlist {
		select {
		case <-ctx.Done():
			break
		default:
		}

		fqdn := word + "." + baseDomain

		rc.acquire()
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			stats.Queried.Add(1)

			ips, cname, err := resolver.resolve(ctx, domain)
			success := err == nil && len(ips) > 0
			defer rc.release(success)

			if !success {
				if err != nil {
					stats.Errors.Add(1)
				}
				return
			}

			if isWildcardMatch(wildcard, ips) {
				return
			}

			confidence := 90
			if cname != "" {
				confidence = 95
			}

			mu.Lock()
			if _, ok := seen[domain]; !ok {
				seen[domain] = struct{}{}
				results = append(results, &subdomainResult{
					domain:     domain,
					ip:         ips[0],
					ips:        ips,
					cname:      cname,
					source:     "brute",
					confidence: confidence,
				})
				stats.Found.Add(1)
			}
			mu.Unlock()
		}(fqdn)
	}

	wg.Wait()
	return results
}

func (m *SubdomainScanner) recursiveBrute(ctx context.Context, found []*subdomainResult, wordlist []string, rc *rateController, resolver *cachedResolver, wildcard wildcardInfo, maxDepth, depth int, stats *ScanStats) []*subdomainResult {
	if depth >= maxDepth || len(found) == 0 {
		return found
	}

	var all []*subdomainResult
	all = append(all, found...)

	shortList := wordlist
	if len(shortList) > 100 {
		shortList = shortList[:100]
	}

	for _, sub := range found {
		select {
		case <-ctx.Done():
			return all
		default:
		}

		deeper := m.bruteForce(ctx, sub.domain, shortList, rc, resolver, wildcard, stats)
		if len(deeper) > 0 {
			all = append(all, deeper...)
			slog.Debug("[*] 递归发现", "parent", sub.domain, "found", len(deeper))
		}
	}

	return all
}

// --- 批量结果丰富 ---

func (m *SubdomainScanner) batchEnrich(ctx context.Context, results map[string]*subdomainResult, resolver *cachedResolver) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, r := range results {
		wg.Add(1)
		sem <- struct{}{}
		go func(rec *subdomainResult) {
			defer wg.Done()
			defer func() { <-sem }()
			m.enrichOne(ctx, rec, resolver)
		}(r)
	}

	wg.Wait()
}

func (m *SubdomainScanner) enrichOne(ctx context.Context, r *subdomainResult, resolver *cachedResolver) {
	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	netResolver := &net.Resolver{PreferGo: true}

	type mxResult struct{ records []string }
	type nsResult struct{ records []string }
	type txtResult struct{ records []string }

	mxCh := make(chan mxResult, 1)
	nsCh := make(chan nsResult, 1)
	txtCh := make(chan txtResult, 1)

	go func() {
		var records []string
		mx, _ := netResolver.LookupMX(ctx2, r.domain)
		for _, m := range mx {
			records = append(records, strings.TrimSuffix(m.Host, "."))
		}
		mxCh <- mxResult{records: records}
	}()

	go func() {
		var records []string
		ns, _ := netResolver.LookupNS(ctx2, r.domain)
		for _, n := range ns {
			records = append(records, strings.TrimSuffix(n.Host, "."))
		}
		nsCh <- nsResult{records: records}
	}()

	go func() {
		txt, _ := netResolver.LookupTXT(ctx2, r.domain)
		txtCh <- txtResult{records: txt}
	}()

	if r.ip == "" && len(r.ips) == 0 {
		ips, cname, _ := resolver.resolve(ctx2, r.domain)
		if len(ips) > 0 {
			r.ip = ips[0]
			r.ips = ips
		}
		if cname != "" {
			r.cname = cname
		}
	}

	select {
	case mr := <-mxCh:
		r.mx = mr.records
	case <-ctx2.Done():
	}
	select {
	case nr := <-nsCh:
		r.ns = nr.records
	case <-ctx2.Done():
	}
	select {
	case tr := <-txtCh:
		r.txt = tr.records
	case <-ctx2.Done():
	}
}

// --- CDN 检测 ---

var cdnCNAMEs = map[string]string{
	"cloudfront.net":   "AWS CloudFront",
	"cloudflare.com":   "Cloudflare",
	"akamaiedge.net":   "Akamai",
	"akamai.net":       "Akamai",
	"fastly.net":       "Fastly",
	"edgekey.net":      "Akamai",
	"azureedge.net":    "Azure CDN",
	"msecnd.net":       "Azure CDN",
	"cdn.dnsv1.com":    "Tencent CDN",
	"kunlun.com":       "Alibaba CDN",
	"alikunlun.com":    "Alibaba CDN",
	"cdngslb.com":      "Alibaba CDN",
	"cdn20.com":        "ChinaNetCenter",
	"aicdn.com":        "Baishan CDN",
	"cdnhwc1.com":      "Huawei CDN",
	"hichina.com":      "Alibaba Cloud",
	"edgesuite.net":    "Akamai",
	"stackpathdns.com": "StackPath",
	"netlify.com":      "Netlify",
	"vercel-dns.com":   "Vercel",
	"incapdns.net":     "Imperva/Incapsula",
}

func detectCDN(r *subdomainResult) string {
	if r.cname != "" {
		for pattern, name := range cdnCNAMEs {
			if strings.Contains(r.cname, pattern) {
				return name
			}
		}
	}

	if len(r.ips) > 2 {
		return "possible_cdn"
	}

	return ""
}

// --- IP 聚合 ---

type ipGroup struct {
	IP      string
	Domains []string
	CClass  string
}

func aggregateByIP(results map[string]*subdomainResult) map[string]*ipGroup {
	groups := make(map[string]*ipGroup)
	for _, r := range results {
		if r.ip == "" {
			continue
		}
		g, ok := groups[r.ip]
		if !ok {
			g = &ipGroup{IP: r.ip, CClass: extractCClass(r.ip)}
			groups[r.ip] = g
		}
		g.Domains = append(g.Domains, r.domain)
	}
	return groups
}

func extractCClass(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ".") + ".0/24"
	}
	return ""
}

// --- 工具 ---

func (m *SubdomainScanner) getWordlist(config map[string]interface{}) []string {
	if config != nil {
		if custom, ok := config["wordlist"].([]string); ok && len(custom) > 0 {
			return custom
		}
		if dictName, ok := config["dict_name"].(string); ok && dictName != "" {
			entries := m.dictStore.Get("subdomain", dictName)
			if len(entries) > 0 {
				return entries
			}
		}
	}
	return m.dictStore.GetSubdomains()
}

func extractDomain(t *engine.Target) string {
	if t.Host != "" && net.ParseIP(t.Host) == nil {
		return t.Host
	}
	if t.URL != "" {
		parts := strings.Split(t.URL, "//")
		if len(parts) > 1 {
			host := strings.Split(parts[1], "/")[0]
			host = strings.Split(host, ":")[0]
			if net.ParseIP(host) == nil {
				return host
			}
		}
	}
	return ""
}

func parseInt(config map[string]interface{}, key string, defaultVal int) int {
	if config != nil {
		if v, ok := config[key]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
	}
	return defaultVal
}

func parseBool(config map[string]interface{}, key string, defaultVal bool) bool {
	if config != nil {
		if v, ok := config[key].(bool); ok {
			return v
		}
	}
	return defaultVal
}

func parseDuration(config map[string]interface{}, key string, defaultVal time.Duration) time.Duration {
	if config != nil {
		if v, ok := config[key].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
	}
	return defaultVal
}

func parseResolvers(config map[string]interface{}) []string {
	if config != nil {
		if v, ok := config["resolvers"].([]string); ok && len(v) > 0 {
			return v
		}
	}
	return nil
}

// --- DNS 缓存解析器 (singleflight + 并行查询) ---

type cachedResolver struct {
	mu        sync.RWMutex
	cache     map[string]*dnsEntry
	inflight  map[string]*inflightEntry
	timeout   time.Duration
	resolvers []string
}

type dnsEntry struct {
	ips   []string
	cname string
	err   error
}

type inflightEntry struct {
	done  chan struct{}
	entry *dnsEntry
}

func newCachedResolver(timeout time.Duration, resolvers []string) *cachedResolver {
	if len(resolvers) == 0 {
		resolvers = []string{"8.8.8.8:53", "1.1.1.1:53", "223.5.5.5:53", "114.114.114.114:53"}
	}
	return &cachedResolver{
		cache:     make(map[string]*dnsEntry),
		inflight:  make(map[string]*inflightEntry),
		timeout:   timeout,
		resolvers: resolvers,
	}
}

func (r *cachedResolver) resolve(ctx context.Context, domain string) ([]string, string, error) {
	r.mu.RLock()
	if entry, ok := r.cache[domain]; ok {
		r.mu.RUnlock()
		return entry.ips, entry.cname, entry.err
	}
	r.mu.RUnlock()

	r.mu.Lock()
	if entry, ok := r.cache[domain]; ok {
		r.mu.Unlock()
		return entry.ips, entry.cname, entry.err
	}
	if inf, ok := r.inflight[domain]; ok {
		r.mu.Unlock()
		select {
		case <-inf.done:
			return inf.entry.ips, inf.entry.cname, inf.entry.err
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	inf := &inflightEntry{done: make(chan struct{})}
	r.inflight[domain] = inf
	r.mu.Unlock()

	entry := r.doResolve(ctx, domain)
	inf.entry = entry

	r.mu.Lock()
	r.cache[domain] = entry
	delete(r.inflight, domain)
	r.mu.Unlock()

	close(inf.done)
	return entry.ips, entry.cname, entry.err
}

func (r *cachedResolver) doResolve(ctx context.Context, domain string) *dnsEntry {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx2 context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			idx := len(domain) % len(r.resolvers)
			return d.DialContext(ctx2, "udp", r.resolvers[idx])
		},
	}

	ctx2, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	type cnameResult struct {
		cname string
	}
	type hostResult struct {
		ips []string
		err error
	}

	cnameCh := make(chan cnameResult, 1)
	hostCh := make(chan hostResult, 1)

	go func() {
		c, _ := resolver.LookupCNAME(ctx2, domain)
		cname := ""
		if c != "" && c != domain+"." {
			cname = strings.TrimSuffix(c, ".")
		}
		cnameCh <- cnameResult{cname: cname}
	}()

	go func() {
		ips, err := resolver.LookupHost(ctx2, domain)
		hostCh <- hostResult{ips: ips, err: err}
	}()

	var cname string
	var ips []string
	var err error

	select {
	case cr := <-cnameCh:
		cname = cr.cname
	case <-ctx2.Done():
	}

	select {
	case hr := <-hostCh:
		ips = hr.ips
		err = hr.err
	case <-ctx2.Done():
		err = ctx2.Err()
	}

	return &dnsEntry{ips: ips, cname: cname, err: err}
}
