package sitemonitor

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"vulnscan-backend/model"
)

const (
	incidentSectionCause    = "【事件成因】"
	incidentSectionEvidence = "【证据详情】"
	incidentSectionTrace    = "【溯源信息】"
)

var monitorDimensionLabel = map[string]string{
	"tamper":         "网站篡改",
	"domain_hijack":  "域名劫持",
	"availability":   "可用性异常",
	"sensitive_word": "敏感词检测",
	"sensitive_file": "敏感文件泄露",
	"blacklink":      "暗链检测",
}

func buildMonitorIncidentCause(exec *model.MonitorExecution, incidentType string) string {
	dimLabel := monitorDimensionLabel[exec.Dimension]
	if dimLabel == "" {
		dimLabel = exec.Dimension
	}
	lines := []string{
		fmt.Sprintf("站点监测在「%s」维度检测到异常，判定为「%s」。", dimLabel, incidentType),
		fmt.Sprintf("监测目标 URL：%s", exec.URL),
	}
	if exec.Error != "" && exec.Status == "failed" {
		lines = append(lines, "执行错误："+exec.Error)
	}
	return strings.Join(lines, "\n")
}

func buildMonitorIncidentEvidence(exec *model.MonitorExecution) string {
	if strings.TrimSpace(exec.ResultJSON) == "" {
		if exec.Error != "" {
			return "监测执行未返回结构化结果。\n执行错误：" + exec.Error
		}
		return "监测执行未返回结构化结果，请在「站点监测 → 执行记录」查看原始详情。"
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(exec.ResultJSON), &result); err != nil {
		return "结果解析失败：" + err.Error()
	}
	switch exec.Dimension {
	case "tamper":
		return formatTamperEvidence(result)
	case "blacklink":
		return formatBlacklinkEvidence(result)
	case "sensitive_word":
		return formatSensitiveWordEvidence(result)
	case "sensitive_file":
		return formatSensitiveFileEvidence(result)
	case "domain_hijack":
		return formatDomainHijackEvidence(result)
	case "availability":
		return formatAvailabilityEvidence(result)
	default:
		return formatGenericMonitorEvidence(result)
	}
}

func buildMonitorIncidentTrace(exec *model.MonitorExecution) string {
	lines := []string{
		"来源：站点监测（自动转事件）",
		fmt.Sprintf("监测执行 ID：%s", exec.ID),
	}
	if exec.PathTaskID != "" {
		lines = append(lines, "路径任务 ID："+exec.PathTaskID)
	}
	if exec.TargetID != "" {
		lines = append(lines, "监测目标 ID："+exec.TargetID)
	}
	if exec.AgentID != "" {
		lines = append(lines, "执行 Agent："+exec.AgentID)
	}
	if exec.StartedAt != nil {
		lines = append(lines, "检测开始："+exec.StartedAt.Format(time.RFC3339))
	}
	if exec.FinishedAt != nil {
		lines = append(lines, "检测结束："+exec.FinishedAt.Format(time.RFC3339))
	}
	return strings.Join(lines, "\n")
}

func buildMonitorIncidentDescription(exec *model.MonitorExecution, incidentType string) string {
	parts := []string{
		incidentSectionCause,
		buildMonitorIncidentCause(exec, incidentType),
		"",
		incidentSectionEvidence,
		buildMonitorIncidentEvidence(exec),
	}
	if detail := buildMonitorIncidentEvidenceDetail(exec); detail != "" {
		parts = append(parts, "", incidentSectionDetail, detail)
	}
	parts = append(parts, "", incidentSectionTrace, buildMonitorIncidentTrace(exec))
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func formatTamperEvidence(result map[string]any) string {
	var b strings.Builder
	if tampered, _ := result["tampered"].(bool); tampered {
		b.WriteString("状态：检测到页面篡改\n")
	}
	if title, _ := result["title"].(string); title != "" {
		b.WriteString("页面标题：" + title + "\n")
	}
	diffs, _ := result["diffs"].([]any)
	if len(diffs) == 0 {
		if hash := mapStr(result, "content_hash"); hash != "" {
			b.WriteString("当前内容 Hash：" + truncateHashStr(hash) + "\n")
		}
		if b.Len() == 0 {
			b.WriteString("未解析到 diff 明细，请对照监测执行详情中的篡改对比。")
		}
		return strings.TrimSpace(b.String())
	}
	b.WriteString(fmt.Sprintf("篡改变更（%d 处）：\n", len(diffs)))
	limit := len(diffs)
	if limit > 12 {
		limit = 12
	}
	for i := 0; i < limit; i++ {
		m, _ := diffs[i].(map[string]any)
		if m == nil {
			continue
		}
		b.WriteString("  - " + formatTamperDiffLine(m) + "\n")
	}
	if len(diffs) > limit {
		b.WriteString(fmt.Sprintf("  … 共 %d 处变更\n", len(diffs)))
	}
	return strings.TrimSpace(b.String())
}

var tamperDiffLabels = map[string]string{
	"content_hash":      "内容 Hash 变化",
	"title":             "页面标题变化",
	"status_code":       "HTTP 状态码变化",
	"text_length":       "可见文本长度异常",
	"injected_elements": "异常注入元素",
}

func formatTamperDiffLine(m map[string]any) string {
	typ := mapStr(m, "type")
	label := tamperDiffLabels[typ]
	if label == "" {
		label = typ
	}
	if label == "" {
		label = "未知变更"
	}
	if typ == "injected_elements" {
		if els, ok := m["elements"].([]any); ok && len(els) > 0 {
			return fmt.Sprintf("%s：发现 %d 处异常元素", label, len(els))
		}
		return label + "：发现异常元素"
	}
	base, hasBase := m["baseline"]
	cur, hasCur := m["current"]
	if hasBase && hasCur {
		baseStr := fmt.Sprint(base)
		curStr := fmt.Sprint(cur)
		if typ == "text_length" {
			if ratio, ok := m["ratio"].(float64); ok && ratio > 0 {
				return fmt.Sprintf("%s：基线 %s 字 → 当前 %s 字（变化约 %.0f%%）", label, baseStr, curStr, ratio*100)
			}
		}
		if typ == "content_hash" {
			return fmt.Sprintf("%s：%s → %s", label, truncateHashStr(baseStr), truncateHashStr(curStr))
		}
		return fmt.Sprintf("%s：%s → %s", label, baseStr, curStr)
	}
	if sev := mapStr(m, "severity"); sev != "" {
		return fmt.Sprintf("[%s] %s", sev, label)
	}
	return label
}

func truncateHashStr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 20 {
		return s
	}
	return s[:10] + "…" + s[len(s)-10:]
}

func formatBlacklinkEvidence(result map[string]any) string {
	var b strings.Builder
	links, _ := result["blacklink_matches"].([]any)
	backdoors, _ := result["backdoor_findings"].([]any)
	if len(links) > 0 {
		b.WriteString(fmt.Sprintf("暗链命中（%d 个）：\n", len(links)))
		for i, item := range links {
			if i >= 8 {
				break
			}
			m, _ := item.(map[string]any)
			url := firstNonEmptyStr(mapStr(m, "url"), mapStr(m, "domain"), "未知链接")
			hidden := ""
			if h, ok := m["hidden"].(bool); ok && h {
				hidden = " [隐藏]"
			}
			b.WriteString(fmt.Sprintf("  - %s%s\n", url, hidden))
		}
	}
	if len(backdoors) > 0 {
		b.WriteString(fmt.Sprintf("后门特征（%d 个）：\n", len(backdoors)))
		for i, item := range backdoors {
			if i >= 5 {
				break
			}
			m, _ := item.(map[string]any)
			b.WriteString("  - " + firstNonEmptyStr(mapStr(m, "path"), mapStr(m, "url"), "未知路径") + "\n")
		}
	}
	if b.Len() == 0 {
		return "检测到暗链/后门风险，但未解析到具体链接列表。"
	}
	return strings.TrimSpace(b.String())
}

func formatSensitiveWordEvidence(result map[string]any) string {
	matches, _ := result["matches"].([]any)
	if len(matches) == 0 {
		return "检测到敏感词风险，但未解析到命中明细。"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("敏感词命中（%d 处）：\n", len(matches)))
	for i, item := range matches {
		if i >= 8 {
			break
		}
		m, _ := item.(map[string]any)
		kw := firstNonEmptyStr(mapStr(m, "keyword"), mapStr(m, "word"))
		sev := mapStr(m, "severity")
		ctx := mapStr(m, "context")
		if len(ctx) > 120 {
			ctx = ctx[:120] + "…"
		}
		line := fmt.Sprintf("  - [%s] \"%s\"", sev, kw)
		if ctx != "" {
			line += " 上下文: " + ctx
		}
		b.WriteString(line + "\n")
	}
	return strings.TrimSpace(b.String())
}

func formatSensitiveFileEvidence(result map[string]any) string {
	files, _ := result["files"].([]any)
	if len(files) == 0 {
		files, _ = result["matches"].([]any)
	}
	if len(files) == 0 {
		return "检测到敏感文件暴露风险，但未解析到文件列表。"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("敏感文件（%d 个）：\n", len(files)))
	for i, item := range files {
		if i >= 8 {
			break
		}
		m, _ := item.(map[string]any)
		b.WriteString("  - " + firstNonEmptyStr(mapStr(m, "path"), mapStr(m, "url"), mapStr(m, "filename"), "未知文件") + "\n")
	}
	return strings.TrimSpace(b.String())
}

func formatDomainHijackEvidence(result map[string]any) string {
	var lines []string
	if hijacked, ok := result["hijacked"].(bool); ok && hijacked {
		lines = append(lines, "状态：检测到域名劫持")
	}
	if ip := mapStr(result, "resolved_ip"); ip != "" {
		lines = append(lines, "解析 IP："+ip)
	}
	if ip := mapStr(result, "expected_ip"); ip != "" {
		lines = append(lines, "预期 IP："+ip)
	}
	if dns := mapStr(result, "dns_provider"); dns != "" {
		lines = append(lines, "DNS 提供方："+dns)
	}
	if len(lines) == 0 {
		return formatGenericMonitorEvidence(result)
	}
	return strings.Join(lines, "\n")
}

func formatAvailabilityEvidence(result map[string]any) string {
	var lines []string
	if available, ok := result["available"].(bool); ok && !available {
		lines = append(lines, "状态：站点不可用或探测失败")
	}
	if code := mapInt(result, "status_code"); code > 0 {
		lines = append(lines, fmt.Sprintf("HTTP 状态码：%d", code))
	}
	if ms := mapInt(result, "response_time_ms"); ms > 0 {
		lines = append(lines, fmt.Sprintf("响应时间：%d ms", ms))
	}
	if errMsg := mapStr(result, "error"); errMsg != "" {
		lines = append(lines, "错误："+errMsg)
	}
	if errs, ok := result["errors"].([]any); ok && len(errs) > 0 {
		for i, e := range errs {
			if i >= 3 {
				break
			}
			lines = append(lines, "  - "+fmt.Sprint(e))
		}
	}
	if len(lines) == 0 {
		return formatGenericMonitorEvidence(result)
	}
	return strings.Join(lines, "\n")
}

func formatGenericMonitorEvidence(result map[string]any) string {
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "监测结果（原始 JSON 无法格式化）"
	}
	s := string(raw)
	if len(s) > 4000 {
		s = s[:4000] + "\n…（已截断）"
	}
	return s
}

func mapStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func mapInt(m map[string]any, key string) int {
	s := mapStr(m, key)
	if s == "" {
		return 0
	}
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
