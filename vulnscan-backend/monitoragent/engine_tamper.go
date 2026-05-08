package monitoragent

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
)

type TamperEngine struct {
	Rules RuleStore
}

func (e *TamperEngine) Name() string { return "tamper" }

func (e *TamperEngine) Run(ctx context.Context, task *TaskMessage, snap *PageSnapshot) (map[string]any, error) {
	result := map[string]any{
		"url":      task.URL,
		"tampered": false,
	}

	if snap == nil || snap.Error != "" {
		result["error"] = "page fetch failed"
		if snap != nil {
			result["error"] = snap.Error
		}
		return result, nil
	}

	result["title"] = snap.Title
	result["status_code"] = snap.StatusCode
	result["content_hash"] = snap.ContentHash
	result["visible_text_length"] = len(snap.VisibleText)

	if task.Baseline == nil {
		result["is_first_run"] = true
		result["baseline_update"] = map[string]any{
			"content_hash":        snap.ContentHash,
			"dom_structure_hash":  fmt.Sprintf("%x", md5.Sum([]byte(extractDOMStructure(snap.RenderedHTML)))),
			"title":               snap.Title,
			"status_code":         snap.StatusCode,
			"visible_text_length": len(snap.VisibleText),
		}
		return result, nil
	}

	diffs := make([]map[string]any, 0)

	if snap.ContentHash != task.Baseline.ContentHash && task.Baseline.ContentHash != "" {
		diffs = append(diffs, map[string]any{
			"type":     "content_hash",
			"baseline": task.Baseline.ContentHash,
			"current":  snap.ContentHash,
		})
	}

	if snap.Title != task.Baseline.Title && task.Baseline.Title != "" {
		diffs = append(diffs, map[string]any{
			"type":     "title",
			"baseline": task.Baseline.Title,
			"current":  snap.Title,
		})
	}

	if snap.StatusCode != task.Baseline.StatusCode && task.Baseline.StatusCode > 0 {
		diffs = append(diffs, map[string]any{
			"type":     "status_code",
			"baseline": task.Baseline.StatusCode,
			"current":  snap.StatusCode,
		})
	}

	textLenDiff := len(snap.VisibleText) - task.Baseline.VisibleTextLength
	if task.Baseline.VisibleTextLength > 0 {
		ratio := float64(abs(textLenDiff)) / float64(task.Baseline.VisibleTextLength)
		if ratio > 0.3 {
			diffs = append(diffs, map[string]any{
				"type":     "text_length",
				"baseline": task.Baseline.VisibleTextLength,
				"current":  len(snap.VisibleText),
				"ratio":    ratio,
			})
		}
	}

	iframeDiff := e.checkInjectedElements(snap)
	if len(iframeDiff) > 0 {
		diffs = append(diffs, map[string]any{
			"type":     "injected_elements",
			"elements": iframeDiff,
		})
	}

	if len(diffs) > 0 {
		result["tampered"] = true
		result["diffs"] = diffs
		result["severity"] = classifySeverity(diffs)
	}

	return result, nil
}

func extractDOMStructure(htmlStr string) string {
	var buf strings.Builder
	inTag := false
	for _, ch := range htmlStr {
		if ch == '<' {
			inTag = true
			buf.WriteRune(ch)
		} else if ch == '>' {
			inTag = false
			buf.WriteRune(ch)
		} else if inTag {
			if ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' {
				continue
			}
			buf.WriteRune(ch)
		}
	}
	return buf.String()
}

func (e *TamperEngine) checkInjectedElements(snap *PageSnapshot) []map[string]any {
	var findings []map[string]any
	trustedCDNs := e.loadTrustedDomains()

	for _, script := range snap.Scripts {
		if script.IsExternal && script.Src != "" {
			domain := extractHost(script.Src)
			pageDomain := extractHost(snap.URL)
			if domain != "" && pageDomain != "" && domain != pageDomain &&
				!matchTrustedDomain(domain, trustedCDNs) {
				findings = append(findings, map[string]any{
					"type":   "external_script",
					"src":    script.Src,
					"domain": domain,
				})
			}
		}
	}

	return findings
}

func (e *TamperEngine) loadTrustedDomains() []string {
	if e.Rules == nil {
		return nil
	}
	data, err := e.Rules.GetModuleRules("tamper")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		TrustedDomains []struct {
			Domain string `json:"domain"`
		} `json:"trusted_domains"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	domains := make([]string, 0, len(cfg.TrustedDomains))
	for _, d := range cfg.TrustedDomains {
		if d.Domain != "" {
			domains = append(domains, d.Domain)
		}
	}
	return domains
}

func matchTrustedDomain(domain string, trusted []string) bool {
	for _, t := range trusted {
		if domain == t || strings.HasSuffix(domain, "."+t) {
			return true
		}
	}
	return false
}

func classifySeverity(diffs []map[string]any) string {
	for _, d := range diffs {
		if d["type"] == "injected_elements" {
			return "critical"
		}
	}
	if len(diffs) >= 3 {
		return "high"
	}
	return "medium"
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
