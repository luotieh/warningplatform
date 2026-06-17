package analyzer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type SuspicionResult struct {
	Score   int                `json:"score"`
	Details []SuspicionFinding `json:"details"`
}

type SuspicionFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Score    int    `json:"score"`
	Desc     string `json:"desc"`
	Evidence string `json:"evidence,omitempty"`
}

func (r SuspicionResult) DetailJSON() string {
	b, _ := json.Marshal(r.Details)
	return string(b)
}

func EvaluateBaselineSuspicion(snap *snapshotData, trustedCDNs []string) SuspicionResult {
	var findings []SuspicionFinding

	findings = append(findings, checkHiddenLinks(snap)...)
	findings = append(findings, checkSuspiciousScripts(snap, trustedCDNs)...)
	findings = append(findings, checkSEOSpam(snap)...)
	findings = append(findings, checkHiddenIframes(snap)...)
	findings = append(findings, checkAnomalousHeaders(snap)...)
	findings = append(findings, checkDarkLinkPatterns(snap)...)

	total := 0
	for _, f := range findings {
		total += f.Score
	}
	if total > 100 {
		total = 100
	}
	return SuspicionResult{Score: total, Details: findings}
}

func checkHiddenLinks(snap *snapshotData) []SuspicionFinding {
	var findings []SuspicionFinding
	hiddenCount := 0
	for _, link := range snap.Links {
		if link.IsHidden && link.IsExternal {
			hiddenCount++
		}
	}
	if hiddenCount > 0 {
		findings = append(findings, SuspicionFinding{
			Rule:     "hidden_external_links",
			Severity: scoreSeverity(hiddenCount * 10),
			Score:    min(hiddenCount*10, 40),
			Desc:     fmt.Sprintf("发现 %d 个隐藏的外部链接（可能为暗链注入）", hiddenCount),
		})
	}
	return findings
}

func checkSuspiciousScripts(snap *snapshotData, trustedCDNs []string) []SuspicionFinding {
	var findings []SuspicionFinding
	untrustedCount := 0
	var samples []string

	pageDomain := extractHost(snap.URL)
	for _, script := range snap.Scripts {
		if !script.IsExternal || script.Src == "" {
			continue
		}
		domain := extractHost(script.Src)
		if domain == "" || sameRootDomain(domain, pageDomain) {
			continue
		}
		if !matchTrustedDomain(domain, trustedCDNs) {
			untrustedCount++
			if len(samples) < 3 {
				samples = append(samples, script.Src)
			}
		}
	}
	if untrustedCount > 0 {
		findings = append(findings, SuspicionFinding{
			Rule:     "untrusted_external_scripts",
			Severity: scoreSeverity(untrustedCount * 15),
			Score:    min(untrustedCount*15, 50),
			Desc:     fmt.Sprintf("发现 %d 个非可信来源的外部脚本", untrustedCount),
			Evidence: strings.Join(samples, " | "),
		})
	}

	for _, script := range snap.Scripts {
		if script.IsExternal || script.Snippet == "" {
			continue
		}
		lower := strings.ToLower(script.Snippet)
		if strings.Contains(lower, "document.write") && (strings.Contains(lower, "iframe") || strings.Contains(lower, "<script")) {
			findings = append(findings, SuspicionFinding{
				Rule:     "inline_script_injection",
				Severity: "high",
				Score:    30,
				Desc:     "发现内联脚本使用 document.write 注入 iframe/script",
				Evidence: truncateStr(script.Snippet, 200),
			})
			break
		}
	}
	return findings
}

var seoSpamPatterns = regexp.MustCompile(`(?i)(赌博|博彩|棋牌|彩票|真人|娱乐城|六合彩|时时彩|威尼斯|澳门|老虎机|百家乐|` +
	`casino|gambling|poker|slot|bet365|` +
	`色情|成人|AV|约炮|小姐|裸聊|` +
	`代孕|代开发票|信用卡套现|刷单|微信投票)`)

func checkSEOSpam(snap *snapshotData) []SuspicionFinding {
	var findings []SuspicionFinding
	text := snap.VisibleText + " " + snap.Title

	matches := seoSpamPatterns.FindAllString(text, -1)
	if len(matches) > 0 {
		unique := make(map[string]struct{})
		for _, m := range matches {
			unique[strings.ToLower(m)] = struct{}{}
		}
		keywords := make([]string, 0, len(unique))
		for k := range unique {
			keywords = append(keywords, k)
		}
		score := min(len(unique)*10, 50)
		findings = append(findings, SuspicionFinding{
			Rule:     "seo_spam_keywords",
			Severity: scoreSeverity(score),
			Score:    score,
			Desc:     fmt.Sprintf("页面中发现 %d 类可疑 SEO 垃圾关键词", len(unique)),
			Evidence: strings.Join(keywords, ", "),
		})
	}
	return findings
}

var hiddenIframeRe = regexp.MustCompile(`(?i)<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*[:=]\s*["']?[01](?:px)?|height\s*[:=]\s*["']?[01](?:px)?)[^>]*>`)

func checkHiddenIframes(snap *snapshotData) []SuspicionFinding {
	var findings []SuspicionFinding
	matches := hiddenIframeRe.FindAllString(snap.RenderedHTML, -1)
	if len(matches) > 0 {
		findings = append(findings, SuspicionFinding{
			Rule:     "hidden_iframes",
			Severity: "high",
			Score:    min(len(matches)*20, 40),
			Desc:     fmt.Sprintf("发现 %d 个隐藏的 iframe 元素", len(matches)),
			Evidence: truncateStr(matches[0], 200),
		})
	}
	return findings
}

func checkAnomalousHeaders(snap *snapshotData) []SuspicionFinding {
	var findings []SuspicionFinding

	if snap.StatusCode >= 300 && snap.StatusCode < 400 {
		findings = append(findings, SuspicionFinding{
			Rule:     "redirect_status",
			Severity: "medium",
			Score:    15,
			Desc:     fmt.Sprintf("首页返回重定向状态码 %d（可能被劫持到其他页面）", snap.StatusCode),
		})
	}

	server := snap.Headers["server"]
	if server != "" {
		lower := strings.ToLower(server)
		if strings.Contains(lower, "openresty") || strings.Contains(lower, "tengine") {
			via := snap.Headers["via"]
			xPowered := snap.Headers["x-powered-by"]
			if via != "" || xPowered != "" {
				findings = append(findings, SuspicionFinding{
					Rule:     "proxy_header_anomaly",
					Severity: "low",
					Score:    5,
					Desc:     "检测到反向代理特征头，站点可能经过中间层代理",
					Evidence: fmt.Sprintf("server=%s via=%s x-powered-by=%s", server, via, xPowered),
				})
			}
		}
	}

	return findings
}

var darkLinkStyleRe = regexp.MustCompile(`(?i)<a[^>]*style\s*=\s*["'][^"']*(?:position\s*:\s*(?:absolute|fixed)[^"']*(?:left|top)\s*:\s*-\d|font-size\s*:\s*0|overflow\s*:\s*hidden[^"']*(?:width|height)\s*:\s*0)[^"']*["'][^>]*href\s*=\s*["']https?://`)

func checkDarkLinkPatterns(snap *snapshotData) []SuspicionFinding {
	var findings []SuspicionFinding
	matches := darkLinkStyleRe.FindAllString(snap.RenderedHTML, -1)
	if len(matches) > 0 {
		findings = append(findings, SuspicionFinding{
			Rule:     "dark_link_css_patterns",
			Severity: "critical",
			Score:    min(len(matches)*15, 50),
			Desc:     fmt.Sprintf("发现 %d 个通过 CSS 手法隐藏的外部链接（典型暗链注入特征）", len(matches)),
			Evidence: truncateStr(matches[0], 200),
		})
	}
	return findings
}

func scoreSeverity(score int) string {
	switch {
	case score >= 40:
		return "critical"
	case score >= 25:
		return "high"
	case score >= 10:
		return "medium"
	default:
		return "low"
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
