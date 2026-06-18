package analyzer

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

type BlacklinkAnalyzer struct {
	rules RuleAccessor
}

func NewBlacklinkAnalyzer(rules RuleAccessor) *BlacklinkAnalyzer {
	return &BlacklinkAnalyzer{rules: rules}
}

func (a *BlacklinkAnalyzer) Dimension() string { return "blacklink" }

func (a *BlacklinkAnalyzer) Analyze(ctx context.Context, input *Input) (*Output, error) {
	snap, err := parseSnapshot(input.SnapshotJSON)
	if err != nil {
		return nil, err
	}

	output := &Output{HasIssue: false}
	if snap.Error != "" {
		return output, nil
	}

	pageDomain := extractHost(input.URL)
	blackRules := a.loadBlackRules()
	backdoorPaths := a.loadBackdoorPaths()
	trustedDomains := loadTrustedDomains(input.Config)

	blacklinks := make([]map[string]any, 0)

	for _, link := range snap.Links {
		if !link.IsExternal {
			continue
		}

		linkDomain := extractHost(link.URL)
		if sameRootDomain(linkDomain, pageDomain) {
			continue
		}
		if isDomainTrusted(linkDomain, trustedDomains) {
			continue
		}

		isBlack := false
		matchedPattern := ""
		matchSeverity := "medium"

		for _, rule := range blackRules {
			if rule.re != nil && rule.re.MatchString(link.URL) {
				isBlack = true
				matchedPattern = rule.pattern
				matchSeverity = rule.severity
				break
			}
		}

		if link.IsHidden {
			isBlack = true
			if matchedPattern == "" {
				matchedPattern = "hidden_link"
			}
			matchSeverity = "high"
		}

		if isBlack {
			blacklinks = append(blacklinks, map[string]any{
				"url":      link.URL,
				"domain":   linkDomain,
				"hidden":   link.IsHidden,
				"pattern":  matchedPattern,
				"severity": matchSeverity,
			})
		}
	}

	backdoorFindings := make([]map[string]any, 0)
	for _, path := range backdoorPaths {
		lowerPath := strings.ToLower(path)
		for _, script := range snap.Scripts {
			if strings.Contains(strings.ToLower(script.Src), lowerPath) {
				backdoorFindings = append(backdoorFindings, map[string]any{
					"path":    path,
					"src":     script.Src,
					"context": "script_src",
				})
			}
		}
	}

	hiddenIframes := detectHiddenIframes(snap, pageDomain, trustedDomains)
	jsRedirects := detectJSRedirectsFromSnap(snap, pageDomain, trustedDomains)
	maliciousJS := detectMaliciousJSPatterns(snap)
	metaRedirect := detectMetaRedirect(snap, pageDomain, trustedDomains)

	var cloakingFindings []map[string]any
	if snap.Cloaking != nil && snap.Cloaking.Detected {
		for _, bot := range snap.Cloaking.BotResults {
			if bot.TitleMatch {
				continue
			}
			lowerTitle := strings.ToLower(bot.BotTitle)
			if strings.Contains(lowerTitle, "403") || strings.Contains(lowerTitle, "forbidden") ||
				strings.Contains(lowerTitle, "401") || strings.Contains(lowerTitle, "access denied") {
				continue
			}
			if bot.Similarity < 0.50 {
				sev := "high"
				if bot.Similarity < 0.30 {
					sev = "critical"
				}
				cloakingFindings = append(cloakingFindings, map[string]any{
					"bot_name":    bot.BotName,
					"similarity":  bot.Similarity,
					"bot_title":   bot.BotTitle,
					"title_match": bot.TitleMatch,
					"severity":    sev,
				})
			}
		}
	}

	allFindings := len(blacklinks) + len(backdoorFindings) + len(hiddenIframes) + len(jsRedirects) + len(maliciousJS) + len(metaRedirect) + len(cloakingFindings)
	if allFindings > 0 {
		output.HasIssue = true
		output.Severity = classifyBlacklinkSeverityFull(blacklinks, backdoorFindings, hiddenIframes, jsRedirects, maliciousJS)
		if len(cloakingFindings) > 0 {
			output.Severity = "critical"
		}
		detailMap := map[string]any{
			"has_black":         true,
			"url":               input.URL,
			"blacklink_matches": blacklinks,
			"backdoor_findings": backdoorFindings,
			"hidden_iframes":    hiddenIframes,
			"js_redirects":      jsRedirects,
			"malicious_js":      maliciousJS,
			"meta_redirects":    metaRedirect,
			"total_links":       len(snap.Links),
			"external_links":    countExternalLinks(snap.Links),
		}
		if len(cloakingFindings) > 0 {
			detailMap["cloaking"] = cloakingFindings
		}
		detailJSON, _ := json.Marshal(detailMap)
		output.DetailsJSON = string(detailJSON)
	}

	return output, nil
}

func detectHiddenIframes(snap *snapshotData, pageDomain string, trustedDomains []string) []map[string]any {
	var findings []map[string]any
	for _, iframe := range snap.Iframes {
		if !iframe.IsExternal {
			continue
		}
		iframeDomain := extractHost(iframe.Src)
		if sameRootDomain(iframeDomain, pageDomain) {
			continue
		}
		if isDomainTrusted(iframeDomain, trustedDomains) {
			continue
		}
		if iframe.IsHidden {
			findings = append(findings, map[string]any{
				"src":      iframe.Src,
				"domain":   iframeDomain,
				"hidden":   true,
				"width":    iframe.Width,
				"height":   iframe.Height,
				"severity": "high",
			})
		}
	}
	return findings
}

func detectJSRedirectsFromSnap(snap *snapshotData, pageDomain string, trustedDomains []string) []map[string]any {
	var findings []map[string]any

	for _, redir := range snap.JSRedirects {
		if isRelativeOrLocalPath(redir.Target) {
			continue
		}
		targetDomain := extractHost(redir.Target)
		if targetDomain != "" && isValidDomain(targetDomain) && !sameRootDomain(targetDomain, pageDomain) && !isDomainTrusted(targetDomain, trustedDomains) {
			severity := "medium"
			if redir.Delay > 0 {
				severity = "high"
			}
			if redir.Type == "setTimeout_redirect" || redir.Type == "setInterval_redirect" {
				severity = "high"
			}
			findings = append(findings, map[string]any{
				"type":     redir.Type,
				"target":   redir.Target,
				"domain":   targetDomain,
				"delay":    redir.Delay,
				"snippet":  redir.Snippet,
				"severity": severity,
			})
		}
	}

	if snap.MetaRedirect != nil {
		targetDomain := extractHost(snap.MetaRedirect.URL)
		if targetDomain != "" && !sameRootDomain(targetDomain, pageDomain) && !isDomainTrusted(targetDomain, trustedDomains) {
			findings = append(findings, map[string]any{
				"type":     "meta_refresh",
				"target":   snap.MetaRedirect.URL,
				"domain":   targetDomain,
				"delay":    snap.MetaRedirect.Seconds,
				"severity": "high",
			})
		}
	}

	if snap.FinalURL != "" && snap.URL != "" {
		origDomain := extractHost(snap.URL)
		finalDomain := extractHost(snap.FinalURL)
		if origDomain != "" && finalDomain != "" && !sameRootDomain(origDomain, finalDomain) && !isDomainTrusted(finalDomain, trustedDomains) {
			findings = append(findings, map[string]any{
				"type":     "server_redirect",
				"target":   snap.FinalURL,
				"domain":   finalDomain,
				"severity": "medium",
			})
		}
	}

	return findings
}

func detectMetaRedirect(snap *snapshotData, pageDomain string, trustedDomains []string) []map[string]any {
	if snap.MetaRedirect == nil {
		return nil
	}
	targetDomain := extractHost(snap.MetaRedirect.URL)
	if targetDomain == "" || sameRootDomain(targetDomain, pageDomain) || isDomainTrusted(targetDomain, trustedDomains) {
		return nil
	}
	return []map[string]any{{
		"url":     snap.MetaRedirect.URL,
		"seconds": snap.MetaRedirect.Seconds,
		"domain":  targetDomain,
	}}
}

var maliciousJSPatterns = []struct {
	re       *regexp.Regexp
	category string
	severity string
	desc     string
}{
	{regexp.MustCompile(`(?i)eval\s*\(\s*(?:unescape|decodeURIComponent|atob|String\.fromCharCode)\s*\(`), "obfuscated_eval", "critical", "混淆eval执行"},
	{regexp.MustCompile(`(?i)document\.write\s*\(\s*(?:unescape|decodeURIComponent|atob)\s*\(`), "obfuscated_write", "high", "混淆document.write"},
	{regexp.MustCompile(`(?i)document\.write(?:ln)?\s*\(\s*['"]<(?:script|iframe)[^>]*src=['"]https?://`), "injected_tag_write", "critical", "动态写入外部script/iframe"},
	{regexp.MustCompile(`(?i)coinhive|cryptonight|minero|coin-?hive|jsecoin|crypto-?loot|authedmine`), "crypto_mining", "critical", "加密货币挖矿脚本"},
	{regexp.MustCompile(`(?i)\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}`), "hex_encoded", "high", "大量十六进制编码字符串"},
	{regexp.MustCompile(`(?i)\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){10,}`), "unicode_encoded", "high", "大量Unicode编码字符串"},
	{regexp.MustCompile(`(?i)String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){10,}`), "charcode_decode", "high", "大量CharCode解码"},
}

func detectMaliciousJSPatterns(snap *snapshotData) []map[string]any {
	var findings []map[string]any
	seen := make(map[string]bool)

	for _, script := range snap.Scripts {
		code := script.Snippet
		if code == "" || utf8.RuneCountInString(code) < 10 {
			continue
		}

		for _, p := range maliciousJSPatterns {
			if seen[p.category] {
				continue
			}
			loc := p.re.FindStringIndex(code)
			if loc == nil {
				continue
			}
			seen[p.category] = true
			start := loc[0] - 80
			if start < 0 {
				start = 0
			}
			end := loc[1] + 120
			if end > len(code) {
				end = len(code)
			}
			snippet := code[start:end]
			if start > 0 {
				snippet = "..." + snippet
			}
			if end < len(code) {
				snippet = snippet + "..."
			}
			if utf8.RuneCountInString(snippet) > 400 {
				runes := []rune(snippet)
				snippet = string(runes[:400]) + "..."
			}
			findings = append(findings, map[string]any{
				"category": p.category,
				"severity": p.severity,
				"desc":     p.desc,
				"snippet":  snippet,
				"src":      script.Src,
			})
		}
	}

	return findings
}

func classifyBlacklinkSeverityFull(links, backdoors, iframes, jsRedirects, maliciousJS []map[string]any) string {
	if len(backdoors) > 0 {
		return "critical"
	}
	if len(iframes) > 0 || len(links) > 0 {
		return "high"
	}
	for _, jr := range jsRedirects {
		if sev, _ := jr["severity"].(string); sev == "high" {
			return "high"
		}
	}
	if len(jsRedirects) > 0 {
		return "medium"
	}
	for _, mjs := range maliciousJS {
		if sev, _ := mjs["severity"].(string); sev == "critical" {
			return "high"
		}
	}
	if len(maliciousJS) > 0 {
		return "low"
	}
	return classifyBlacklinkSeverity(links, backdoors)
}

func classifyBlacklinkSeverity(links []map[string]any, backdoors []map[string]any) string {
	if len(backdoors) > 0 {
		return "critical"
	}
	hiddenCount := 0
	for _, l := range links {
		if h, ok := l["hidden"].(bool); ok && h {
			hiddenCount++
		}
		if sev, ok := l["severity"].(string); ok && sev == "critical" {
			return "critical"
		}
	}
	if hiddenCount > 3 || len(links) > 5 {
		return "high"
	}
	if hiddenCount > 0 || len(links) > 2 {
		return "medium"
	}
	return "low"
}

type blacklinkRule struct {
	pattern  string
	re       *regexp.Regexp
	severity string
}

func (a *BlacklinkAnalyzer) loadBlackRules() []blacklinkRule {
	if a.rules == nil {
		return nil
	}
	data, err := a.rules.GetModuleRules("blacklink")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		Rules []struct {
			Re       string `json:"re"`
			Mark     string `json:"mark"`
			Severity string `json:"severity"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	rules := make([]blacklinkRule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		if r.Re == "" {
			continue
		}
		compiled, err := regexp.Compile("(?i)" + r.Re)
		if err != nil {
			continue
		}
		sev := r.Severity
		if sev == "" {
			sev = "medium"
		}
		rules = append(rules, blacklinkRule{pattern: r.Re, re: compiled, severity: sev})
	}
	return rules
}

func (a *BlacklinkAnalyzer) loadBackdoorPaths() []string {
	if a.rules == nil {
		return nil
	}
	data, err := a.rules.GetModuleRules("blacklink")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		BackdoorPaths []struct {
			Path string `json:"path"`
		} `json:"backdoor_paths"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	paths := make([]string, 0, len(cfg.BackdoorPaths))
	for _, e := range cfg.BackdoorPaths {
		if e.Path != "" {
			paths = append(paths, e.Path)
		}
	}
	return paths
}

// isRelativeOrLocalPath 判断 URL 是否为站内相对路径。
func isRelativeOrLocalPath(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return true
	}
	if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
		return true
	}
	if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") {
		return true
	}
	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "?") {
		return true
	}
	if !strings.Contains(target, "://") && !strings.HasPrefix(target, "//") {
		if !strings.Contains(target, ".") || strings.HasSuffix(strings.Split(target, "?")[0], ".html") ||
			strings.HasSuffix(strings.Split(target, "?")[0], ".htm") ||
			strings.HasSuffix(strings.Split(target, "?")[0], ".php") ||
			strings.HasSuffix(strings.Split(target, "?")[0], ".jsp") ||
			strings.HasSuffix(strings.Split(target, "?")[0], ".asp") ||
			strings.HasSuffix(strings.Split(target, "?")[0], ".aspx") {
			return true
		}
	}
	return false
}

// isValidDomain 判断提取的域名是否有效（至少包含一个点号且不是纯文件名）。
func isValidDomain(domain string) bool {
	if domain == "" || domain == "." || domain == ".." {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	if strings.HasPrefix(domain, ".") {
		return false
	}
	return true
}

func countExternalLinks(links []linkInfo) int {
	c := 0
	for _, l := range links {
		if l.IsExternal {
			c++
		}
	}
	return c
}

// loadTrustedDomains 从配置中读取信任域名白名单（trusted_domains）。
// 支持格式：["example.com", "*.example.cn"] 或逗号分隔字符串。
func loadTrustedDomains(cfg map[string]any) []string {
	if cfg == nil {
		return nil
	}
	raw, ok := cfg["trusted_domains"]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		domains := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				domains = append(domains, strings.ToLower(strings.TrimSpace(s)))
			}
		}
		return domains
	case string:
		parts := strings.Split(v, ",")
		domains := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.ToLower(strings.TrimSpace(p))
			if p != "" {
				domains = append(domains, p)
			}
		}
		return domains
	}
	return nil
}

// isDomainTrusted 检查域名是否在信任白名单中。
// 支持精确匹配和通配符匹配（*.example.com 匹配 sub.example.com）。
func isDomainTrusted(domain string, trustedDomains []string) bool {
	if len(trustedDomains) == 0 {
		return false
	}
	domain = strings.ToLower(domain)
	for _, td := range trustedDomains {
		if td == domain {
			return true
		}
		if strings.HasPrefix(td, "*.") {
			suffix := td[1:] // ".example.com"
			if strings.HasSuffix(domain, suffix) || domain == td[2:] {
				return true
			}
		}
		if sameRootDomain(domain, td) {
			return true
		}
	}
	return false
}
