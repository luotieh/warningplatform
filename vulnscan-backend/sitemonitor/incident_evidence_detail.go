package sitemonitor

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"

	"vulnscan-backend/model"
)

const (
	incidentSectionDetail  = "【详细证据】"
	maxIncidentDetailRunes = 24000
)

var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

func buildMonitorIncidentEvidenceDetail(exec *model.MonitorExecution) string {
	if strings.TrimSpace(exec.ResultJSON) == "" {
		return ""
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(exec.ResultJSON), &result); err != nil {
		return ""
	}
	var detail string
	switch exec.Dimension {
	case "tamper":
		detail = formatTamperEvidenceDetail(result)
	case "sensitive_word":
		detail = formatSensitiveWordEvidenceDetail(result)
	case "blacklink":
		detail = formatBlacklinkEvidenceDetail(result)
	case "sensitive_file":
		detail = formatSensitiveFileEvidenceDetail(result)
	case "domain_hijack":
		detail = formatDomainHijackEvidenceDetail(result)
	case "availability":
		detail = formatAvailabilityEvidenceDetail(result)
	default:
		detail = formatGenericMonitorEvidence(result)
	}
	return truncateRunes(strings.TrimSpace(detail), maxIncidentDetailRunes)
}

func formatTamperEvidenceDetail(result map[string]any) string {
	var b strings.Builder

	if title := mapStr(result, "title"); title != "" {
		b.WriteString("页面标题：" + title + "\n")
	}
	if url := mapStr(result, "url"); url != "" {
		b.WriteString("页面 URL：" + url + "\n")
	}
	if code := mapInt(result, "status_code"); code > 0 {
		b.WriteString(fmt.Sprintf("HTTP 状态码：%d\n", code))
	}

	diffs, _ := result["diffs"].([]any)
	for _, item := range diffs {
		m, _ := item.(map[string]any)
		if m == nil || mapStr(m, "type") != "injected_elements" {
			continue
		}
		els, _ := m["elements"].([]any)
		if len(els) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("\n异常注入元素（%d 个）：\n", len(els)))
		for i, el := range els {
			if i >= 20 {
				b.WriteString(fmt.Sprintf("  … 共 %d 个\n", len(els)))
				break
			}
			em, _ := el.(map[string]any)
			if em == nil {
				continue
			}
			b.WriteString(fmt.Sprintf("  %d. 类型=%s 域名=%s\n     地址=%s\n",
				i+1,
				firstNonEmptyStr(mapStr(em, "type"), "unknown"),
				mapStr(em, "domain"),
				firstNonEmptyStr(mapStr(em, "src"), mapStr(em, "href"), "-"),
			))
		}
	}

	ev, _ := result["evidence"].(map[string]any)
	if ev == nil {
		if b.Len() == 0 {
			return "无 HTML 对比证据；请查看监测执行详情。"
		}
		return strings.TrimSpace(b.String())
	}

	baseHTML := mapStr(ev, "baseline_html")
	curHTML := mapStr(ev, "current_html")
	if baseHTML == "" && curHTML == "" {
		return strings.TrimSpace(b.String())
	}

	if truncated, _ := ev["truncated"].(bool); truncated {
		b.WriteString("\n（页面正文较长，以下内容为截断摘录；完整双栏对比见监测执行记录）\n")
	}

	b.WriteString("\n════════ 内容对比（文本摘录，[-] 为相对基线删除，[+] 为相对基线新增） ════════\n")

	if baseHTML != "" && curHTML != "" && baseHTML == curHTML {
		b.WriteString("\n【基线全文（首次建立）】\n")
		b.WriteString(truncateRunes(htmlEvidenceToPlain(baseHTML), maxIncidentDetailRunes/2))
	} else {
		if baseHTML != "" {
			b.WriteString("\n【基线 / 相对删除】\n")
			b.WriteString(truncateRunes(htmlEvidenceToPlain(baseHTML), maxIncidentDetailRunes/2))
		}
		if curHTML != "" {
			b.WriteString("\n\n【当前 / 相对新增】\n")
			b.WriteString(truncateRunes(htmlEvidenceToPlain(curHTML), maxIncidentDetailRunes/2))
		}
	}

	return strings.TrimSpace(b.String())
}

func htmlEvidenceToPlain(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, `<del class="tp-del">`, "\n[-")
	s = strings.ReplaceAll(s, `</del>`, "-]\n")
	s = strings.ReplaceAll(s, `<ins class="tp-ins">`, "\n[+")
	s = strings.ReplaceAll(s, `</ins>`, "+]\n")
	s = strings.ReplaceAll(s, `<mark class="sw-hit sw-hit--high">`, "\n【敏感词·高】")
	s = strings.ReplaceAll(s, `<mark class="sw-hit sw-hit--medium">`, "\n【敏感词·中】")
	s = strings.ReplaceAll(s, `<mark class="sw-hit sw-hit--low">`, "\n【敏感词·低】")
	s = strings.ReplaceAll(s, `<mark class="sw-hit">`, "\n【敏感词】")
	s = strings.ReplaceAll(s, `</mark>`, "【/敏感词】\n")
	s = htmlTagRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	return normalizeEvidenceWhitespace(s)
}

func normalizeEvidenceWhitespace(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, " \t")
		if line == "" && len(out) > 0 && out[len(out)-1] == "" {
			continue
		}
		out = append(out, line)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func formatSensitiveWordEvidenceDetail(result map[string]any) string {
	var b strings.Builder
	matches, _ := result["matches"].([]any)
	if len(matches) > 0 {
		b.WriteString(fmt.Sprintf("敏感词命中明细（共 %d 处）：\n", len(matches)))
		for i, item := range matches {
			if i >= 30 {
				b.WriteString(fmt.Sprintf("… 另有 %d 处未列出\n", len(matches)-i))
				break
			}
			m, _ := item.(map[string]any)
			if m == nil {
				continue
			}
			kw := firstNonEmptyStr(mapStr(m, "keyword"), mapStr(m, "word"))
			sev := mapStr(m, "severity")
			b.WriteString(fmt.Sprintf("\n[%d] 词条=\"%s\" 级别=%s\n", i+1, kw, sev))
			if u := mapStr(m, "url"); u != "" {
				b.WriteString("    页面：" + u + "\n")
			}
			if ctx := mapStr(m, "context"); ctx != "" {
				b.WriteString("    上下文：" + ctx + "\n")
			}
			if ctxs, ok := m["contexts"].([]any); ok {
				for j, c := range ctxs {
					if j >= 5 {
						break
					}
					b.WriteString(fmt.Sprintf("    片段%d：%s\n", j+1, fmt.Sprint(c)))
				}
			}
		}
	}

	if pageHTML := mapStr(result, "page_evidence_html"); pageHTML != "" {
		b.WriteString("\n════════ 页面全文摘录（敏感词已标注） ════════\n")
		b.WriteString(truncateRunes(htmlEvidenceToPlain(pageHTML), maxIncidentDetailRunes))
	} else if b.Len() == 0 {
		return "未包含敏感词命中明细。"
	}
	return strings.TrimSpace(b.String())
}

func formatBlacklinkEvidenceDetail(result map[string]any) string {
	var b strings.Builder
	if total := mapInt(result, "total_links"); total > 0 {
		b.WriteString(fmt.Sprintf("页面链接总数：%d\n", total))
	}
	if ext := mapInt(result, "external_links"); ext > 0 {
		b.WriteString(fmt.Sprintf("外链数量：%d\n", ext))
	}
	links, _ := result["blacklink_matches"].([]any)
	if len(links) > 0 {
		b.WriteString(fmt.Sprintf("\n暗链明细（%d 个）：\n", len(links)))
		for i, item := range links {
			if i >= 25 {
				b.WriteString(fmt.Sprintf("… 共 %d 个\n", len(links)))
				break
			}
			m, _ := item.(map[string]any)
			if m == nil {
				continue
			}
			hidden := ""
			if h, ok := m["hidden"].(bool); ok && h {
				hidden = " [隐藏]"
			}
			b.WriteString(fmt.Sprintf("  %d. %s%s\n", i+1,
				firstNonEmptyStr(mapStr(m, "url"), mapStr(m, "domain"), "未知"),
				hidden))
			if p := mapStr(m, "pattern"); p != "" {
				b.WriteString("     匹配规则：" + p + "\n")
			}
		}
	}
	backdoors, _ := result["backdoor_findings"].([]any)
	if len(backdoors) > 0 {
		b.WriteString(fmt.Sprintf("\n后门特征（%d 个）：\n", len(backdoors)))
		for i, item := range backdoors {
			if i >= 15 {
				break
			}
			m, _ := item.(map[string]any)
			if m == nil {
				continue
			}
			b.WriteString(fmt.Sprintf("  %d. 特征路径=%s\n     脚本地址=%s\n     上下文=%s\n",
				i+1, mapStr(m, "path"), mapStr(m, "src"), mapStr(m, "context")))
		}
	}
	if b.Len() == 0 {
		return "未解析到暗链/后门明细。"
	}
	return strings.TrimSpace(b.String())
}

func formatSensitiveFileEvidenceDetail(result map[string]any) string {
	files, _ := result["files"].([]any)
	if len(files) == 0 {
		files, _ = result["matches"].([]any)
	}
	if len(files) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("敏感文件明细（%d 个）：\n", len(files)))
	for i, item := range files {
		if i >= 30 {
			b.WriteString(fmt.Sprintf("… 共 %d 个\n", len(files)))
			break
		}
		m, _ := item.(map[string]any)
		if m == nil {
			continue
		}
		b.WriteString(fmt.Sprintf("  %d. %s\n", i+1,
			firstNonEmptyStr(mapStr(m, "path"), mapStr(m, "url"), mapStr(m, "filename"), "未知")))
		if risk := mapStr(m, "risk"); risk != "" {
			b.WriteString("     风险：" + risk + "\n")
		}
		if mark := mapStr(m, "mark"); mark != "" {
			b.WriteString("     标记：" + mark + "\n")
		}
	}
	return strings.TrimSpace(b.String())
}

func formatDomainHijackEvidenceDetail(result map[string]any) string {
	var lines []string
	for _, key := range []string{
		"hijacked", "resolved_ip", "expected_ip", "expected_ips",
		"dns_provider", "cname", "error", "message",
	} {
		if v, ok := result[key]; ok && fmt.Sprint(v) != "" {
			lines = append(lines, fmt.Sprintf("%s：%v", key, v))
		}
	}
	if records, ok := result["dns_records"].([]any); ok && len(records) > 0 {
		lines = append(lines, fmt.Sprintf("DNS 记录（%d 条）：", len(records)))
		for i, r := range records {
			if i >= 10 {
				break
			}
			lines = append(lines, "  - "+fmt.Sprint(r))
		}
	}
	return strings.Join(lines, "\n")
}

func formatAvailabilityEvidenceDetail(result map[string]any) string {
	var b strings.Builder
	appendMapSection(&b, "耗时分解 (ms)", result["timing"])
	appendMapSection(&b, "DNS", result["dns"])
	appendMapSection(&b, "HTTP", result["http"])
	appendMapSection(&b, "SSL/TLS", result["ssl"])
	if errs, ok := result["errors"].([]any); ok && len(errs) > 0 {
		b.WriteString("\n错误信息：\n")
		for i, e := range errs {
			if i >= 10 {
				break
			}
			b.WriteString("  - " + fmt.Sprint(e) + "\n")
		}
	}
	if warns, ok := result["warnings"].([]any); ok && len(warns) > 0 {
		b.WriteString("\n告警：\n")
		for i, w := range warns {
			if i >= 10 {
				break
			}
			b.WriteString("  - " + fmt.Sprint(w) + "\n")
		}
	}
	if issues, ok := result["security_issues"].([]any); ok && len(issues) > 0 {
		b.WriteString(fmt.Sprintf("\n安全问题（%d 项）：\n", len(issues)))
		for i, item := range issues {
			if i >= 15 {
				break
			}
			b.WriteString("  - " + fmt.Sprint(item) + "\n")
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return strings.TrimSpace(b.String())
}

func appendMapSection(b *strings.Builder, title string, v any) {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return
	}
	b.WriteString("\n" + title + "：\n")
	for k, val := range m {
		if val == nil {
			continue
		}
		switch tv := val.(type) {
		case map[string]any, []any:
			js, err := json.Marshal(tv)
			if err == nil && len(js) > 0 && string(js) != "null" {
				b.WriteString(fmt.Sprintf("  %s：%s\n", k, js))
			}
		default:
			s := fmt.Sprint(val)
			if s != "" {
				b.WriteString(fmt.Sprintf("  %s：%s\n", k, s))
			}
		}
	}
}

func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "\n…（内容已截断，完整证据见监测执行记录）"
}
