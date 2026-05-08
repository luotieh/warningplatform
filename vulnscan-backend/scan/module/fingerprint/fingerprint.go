package fingerprint

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
	"vulnscan-backend/scan/engine"
)

type WebFingerprinter struct {
	db     *gorm.DB
	client *http.Client
	mu     sync.RWMutex
	rules  []FingerprintRule
	loaded bool
}

type FingerprintRule struct {
	Product     string
	Version     string
	Category    string
	Headers     map[string]*regexp.Regexp
	Body        []*regexp.Regexp
	Favicon     string
	Meta        map[string]*regexp.Regexp
	VersionExpr *regexp.Regexp
	Priority    int
}

type FingerprintMatch struct {
	Product  string `json:"product"`
	Version  string `json:"version"`
	Category string `json:"category"`
}

func New() *WebFingerprinter {
	return newFingerprinter(nil)
}

func NewWithDB(db *gorm.DB) *WebFingerprinter {
	return newFingerprinter(db)
}

func newFingerprinter(db *gorm.DB) *WebFingerprinter {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &WebFingerprinter{
		db: db,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (m *WebFingerprinter) ID() string       { return "web_fingerprint" }
func (m *WebFingerprinter) Name() string     { return "Web 指纹识别" }
func (m *WebFingerprinter) Category() string { return "recon" }

func (m *WebFingerprinter) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}

	m.ensureRulesLoaded()

	m.mu.RLock()
	rules := m.rules
	m.mu.RUnlock()

	if len(rules) == 0 {
		return result, nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, t := range targets {
		if !isHTTPTarget(t) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target *engine.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			matches := m.fingerprint(ctx, target, rules)
			if len(matches) == 0 {
				return
			}

			for _, match := range matches {
				finding := &engine.Finding{
					ModuleID:   m.ID(),
					Target:     target,
					Type:       "fingerprint",
					Title:      fmt.Sprintf("检测到 %s", match.Product),
					Severity:   "info",
					Confidence: 80,
					Timestamp:  time.Now(),
					Data: map[string]string{
						"product":  match.Product,
						"version":  match.Version,
						"category": match.Category,
					},
				}

				mu.Lock()
				result.Findings = append(result.Findings, finding)
				mu.Unlock()
			}
		}(t)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] Web指纹识别完成",
		"targets", len(targets),
		"rules", len(rules),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *WebFingerprinter) ensureRulesLoaded() {
	m.mu.RLock()
	if m.loaded {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loaded {
		return
	}

	m.rules = builtinRules()

	if m.db != nil {
		dbRules := m.loadFromDB()
		m.rules = append(dbRules, m.rules...)
		slog.Info("[+] Web指纹规则加载完成", "db_rules", len(dbRules), "builtin_rules", len(builtinRules()), "total", len(m.rules))
	}

	m.loaded = true
}

func (m *WebFingerprinter) loadFromDB() []FingerprintRule {
	var records []model.WebFingerprint
	if err := m.db.Where("status = ?", "active").Order("priority DESC").Find(&records).Error; err != nil {
		slog.Warn("[!] 从DB加载Web指纹失败", "error", err)
		return nil
	}

	var rules []FingerprintRule
	for _, rec := range records {
		rule, err := compileDBRule(rec)
		if err != nil {
			slog.Debug("[!] 编译Web指纹规则失败", "product", rec.Product, "error", err)
			continue
		}
		rules = append(rules, *rule)
	}
	return rules
}

func compileDBRule(rec model.WebFingerprint) (*FingerprintRule, error) {
	rule := &FingerprintRule{
		Product:  rec.Product,
		Version:  rec.Version,
		Category: rec.Category,
		Priority: rec.Priority,
		Favicon:  rec.FaviconHash,
	}

	if rec.HeaderRules != "" {
		var headerMap map[string]string
		if err := json.Unmarshal([]byte(rec.HeaderRules), &headerMap); err != nil {
			return nil, fmt.Errorf("header_rules JSON无效: %w", err)
		}
		rule.Headers = make(map[string]*regexp.Regexp, len(headerMap))
		for key, pattern := range headerMap {
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				return nil, fmt.Errorf("header正则编译失败 [%s]: %w", key, err)
			}
			rule.Headers[key] = re
		}
	}

	if rec.BodyRules != "" {
		var bodyPatterns []string
		if err := json.Unmarshal([]byte(rec.BodyRules), &bodyPatterns); err != nil {
			return nil, fmt.Errorf("body_rules JSON无效: %w", err)
		}
		rule.Body = make([]*regexp.Regexp, 0, len(bodyPatterns))
		for _, pattern := range bodyPatterns {
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				slog.Debug("[!] body正则编译失败", "product", rec.Product, "pattern", pattern)
				continue
			}
			rule.Body = append(rule.Body, re)
		}
	}

	if rec.MetaRules != "" {
		var metaMap map[string]string
		if err := json.Unmarshal([]byte(rec.MetaRules), &metaMap); err == nil {
			rule.Meta = make(map[string]*regexp.Regexp, len(metaMap))
			for key, pattern := range metaMap {
				if re, err := regexp.Compile("(?i)" + pattern); err == nil {
					rule.Meta[key] = re
				}
			}
		}
	}

	if rec.VersionExpr != "" {
		if re, err := regexp.Compile(rec.VersionExpr); err == nil {
			rule.VersionExpr = re
		}
	}

	if len(rule.Headers) == 0 && len(rule.Body) == 0 && rule.Favicon == "" && len(rule.Meta) == 0 {
		return nil, fmt.Errorf("规则无有效匹配条件")
	}

	return rule, nil
}

func (m *WebFingerprinter) fingerprint(ctx context.Context, target *engine.Target, rules []FingerprintRule) []FingerprintMatch {
	url := buildURL(target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}
	body := string(bodyBytes)

	var matches []FingerprintMatch

	for _, rule := range rules {
		if m.matchRule(rule, resp.Header, body) {
			match := FingerprintMatch{
				Product:  rule.Product,
				Version:  rule.Version,
				Category: rule.Category,
			}
			if rule.Version == "" {
				match.Version = extractVersion(rule, body)
			}
			matches = append(matches, match)
		}
	}

	faviconHash := m.fetchFaviconHash(ctx, target)
	if faviconHash != "" {
		for _, rule := range rules {
			if rule.Favicon != "" && rule.Favicon == faviconHash {
				matches = append(matches, FingerprintMatch{
					Product:  rule.Product,
					Version:  rule.Version,
					Category: rule.Category,
				})
			}
		}
	}

	return dedup(matches)
}

func (m *WebFingerprinter) matchRule(rule FingerprintRule, headers http.Header, body string) bool {
	headerMatched := len(rule.Headers) == 0
	if !headerMatched {
		allMatch := true
		for key, re := range rule.Headers {
			val := headers.Get(key)
			if val == "" || !re.MatchString(val) {
				allMatch = false
				break
			}
		}
		headerMatched = allMatch
	}

	bodyMatched := len(rule.Body) == 0
	if !bodyMatched {
		for _, re := range rule.Body {
			if re.MatchString(body) {
				bodyMatched = true
				break
			}
		}
	}

	metaMatched := len(rule.Meta) == 0
	if !metaMatched {
		for name, re := range rule.Meta {
			metaRe := regexp.MustCompile(fmt.Sprintf(
				`(?i)<meta[^>]+name=["']%s["'][^>]+content=["']([^"']+)["']`,
				regexp.QuoteMeta(name),
			))
			if sub := metaRe.FindStringSubmatch(body); len(sub) > 1 && re.MatchString(sub[1]) {
				metaMatched = true
				break
			}
		}
	}

	hasCondition := len(rule.Headers) > 0 || len(rule.Body) > 0 || len(rule.Meta) > 0
	return headerMatched && bodyMatched && metaMatched && hasCondition
}

func (m *WebFingerprinter) fetchFaviconHash(ctx context.Context, target *engine.Target) string {
	url := buildURL(target) + "/favicon.ico"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil || len(data) == 0 {
		return ""
	}

	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// Reload 支持热重载指纹规则
func (m *WebFingerprinter) Reload() {
	m.mu.Lock()
	m.loaded = false
	m.rules = nil
	m.mu.Unlock()

	m.ensureRulesLoaded()
}

func buildURL(target *engine.Target) string {
	if target.URL != "" {
		return target.URL
	}
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}
	scheme := "http"
	if target.Port == 443 || target.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, target.Port)
}

func isHTTPTarget(t *engine.Target) bool {
	if t.URL != "" {
		return true
	}
	httpPorts := map[int]bool{
		80: true, 443: true, 8080: true, 8443: true,
		8000: true, 8888: true, 3000: true, 5000: true,
		9090: true, 8081: true, 8088: true, 8090: true,
	}
	return httpPorts[t.Port]
}

func extractVersion(rule FingerprintRule, body string) string {
	if rule.VersionExpr != nil {
		if sub := rule.VersionExpr.FindStringSubmatch(body); len(sub) > 1 {
			return sub[1]
		}
	}
	versionRe := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(rule.Product) + `[\s/v]*(\d+[\.\d]*)`)
	if sub := versionRe.FindStringSubmatch(body); len(sub) > 1 {
		return sub[1]
	}
	return ""
}

func dedup(matches []FingerprintMatch) []FingerprintMatch {
	seen := make(map[string]bool)
	var result []FingerprintMatch
	for _, match := range matches {
		key := match.Product + "|" + match.Version
		if !seen[key] {
			seen[key] = true
			result = append(result, match)
		}
	}
	return result
}

func builtinRules() []FingerprintRule {
	return []FingerprintRule{
		{Product: "Nginx", Category: "web-server", Priority: 90, Headers: map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)nginx`)}},
		{Product: "Apache", Category: "web-server", Priority: 90, Headers: map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)apache`)}},
		{Product: "IIS", Category: "web-server", Priority: 90, Headers: map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)Microsoft-IIS`)}},
		{Product: "Tomcat", Category: "web-server", Priority: 80, Body: []*regexp.Regexp{regexp.MustCompile(`(?i)Apache Tomcat`)}},
		{Product: "Spring Boot", Category: "framework", Priority: 70, Headers: map[string]*regexp.Regexp{"X-Application-Context": regexp.MustCompile(`.+`)}},
		{Product: "WordPress", Category: "cms", Priority: 80, Body: []*regexp.Regexp{regexp.MustCompile(`(?i)wp-content|wp-includes`)}},
		{Product: "jQuery", Category: "js-library", Priority: 60, Body: []*regexp.Regexp{regexp.MustCompile(`(?i)jquery[.\-/](\d[\d.]*)`)}, VersionExpr: regexp.MustCompile(`(?i)jquery[.\-/v]*(\d+[\.\d]+)`)},
		{Product: "React", Category: "js-framework", Priority: 60, Body: []*regexp.Regexp{regexp.MustCompile(`(?i)__NEXT_DATA__|react-root|_reactRootContainer`)}},
		{Product: "Vue.js", Category: "js-framework", Priority: 60, Body: []*regexp.Regexp{regexp.MustCompile(`(?i)vue\.js|vue\.min\.js|data-v-[a-f0-9]`)}},
		{Product: "Nacos", Category: "microservice", Priority: 70, Body: []*regexp.Regexp{regexp.MustCompile(`(?i)nacos`)}, Headers: map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)nacos`)}},
		{Product: "Grafana", Category: "monitor", Priority: 70, Body: []*regexp.Regexp{regexp.MustCompile(`(?i)grafana`)}},
		{Product: "Jenkins", Category: "ci-cd", Priority: 70, Headers: map[string]*regexp.Regexp{"X-Jenkins": regexp.MustCompile(`.+`)}},
		{Product: "PHP", Category: "language", Priority: 80, Headers: map[string]*regexp.Regexp{"X-Powered-By": regexp.MustCompile(`(?i)PHP`)}},
	}
}
