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

	blacklinks := make([]map[string]any, 0)

	for _, link := range snap.Links {
		if !link.IsExternal {
			continue
		}

		linkDomain := extractHost(link.URL)
		if linkDomain == pageDomain {
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

	hiddenIframes := detectHiddenIframes(snap, pageDomain)
	jsRedirects := detectJSRedirectsFromSnap(snap, pageDomain)
	maliciousJS := detectMaliciousJSPatterns(snap)
	metaRedirect := detectMetaRedirect(snap, pageDomain)

	var cloakingFindings []map[string]any
	if snap.Cloaking != nil && snap.Cloaking.Detected {
		for _, bot := range snap.Cloaking.BotResults {
			if bot.Similarity < 0.70 {
				cloakingFindings = append(cloakingFindings, map[string]any{
					"bot_name":   bot.BotName,
					"similarity": bot.Similarity,
					"bot_title":  bot.BotTitle,
					"severity":   "critical",
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

func detectHiddenIframes(snap *snapshotData, pageDomain string) []map[string]any {
	var findings []map[string]any
	for _, iframe := range snap.Iframes {
		if !iframe.IsExternal {
			continue
		}
		iframeDomain := extractHost(iframe.Src)
		if iframeDomain == pageDomain {
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

func detectJSRedirectsFromSnap(snap *snapshotData, pageDomain string) []map[string]any {
	var findings []map[string]any

	for _, redir := range snap.JSRedirects {
		targetDomain := extractHost(redir.Target)
		if targetDomain != "" && targetDomain != pageDomain {
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
		if targetDomain != "" && targetDomain != pageDomain {
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
		if origDomain != "" && finalDomain != "" && origDomain != finalDomain {
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

func detectMetaRedirect(snap *snapshotData, pageDomain string) []map[string]any {
	if snap.MetaRedirect == nil {
		return nil
	}
	targetDomain := extractHost(snap.MetaRedirect.URL)
	if targetDomain == "" || targetDomain == pageDomain {
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
	{regexp.MustCompile(`(?i)(?:createElement|appendChild)\s*\([^)]*(?:script|iframe)`), "dynamic_element", "high", "动态创建script/iframe元素"},
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
			if m := p.re.FindString(code); m != "" {
				seen[p.category] = true
				snippet := m
				if len(snippet) > 200 {
					snippet = snippet[:200]
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
	}

	return findings
}

func classifyBlacklinkSeverityFull(links, backdoors, iframes, jsRedirects, maliciousJS []map[string]any) string {
	if len(backdoors) > 0 {
		return "critical"
	}
	for _, mjs := range maliciousJS {
		if sev, _ := mjs["severity"].(string); sev == "critical" {
			return "critical"
		}
	}
	if len(iframes) > 0 {
		return "high"
	}
	for _, jr := range jsRedirects {
		if sev, _ := jr["severity"].(string); sev == "high" {
			return "high"
		}
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

func countExternalLinks(links []linkInfo) int {
	c := 0
	for _, l := range links {
		if l.IsExternal {
			c++
		}
	}
	return c
}
