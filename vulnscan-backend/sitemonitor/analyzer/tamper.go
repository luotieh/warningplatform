package analyzer

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"

	"vulnscan-backend/model"
)

type TamperAnalyzer struct {
	rules RuleAccessor
}

func NewTamperAnalyzer(rules RuleAccessor) *TamperAnalyzer {
	return &TamperAnalyzer{rules: rules}
}

func (a *TamperAnalyzer) Dimension() string { return "tamper" }

func (a *TamperAnalyzer) Analyze(ctx context.Context, input *Input) (*Output, error) {
	snap, err := parseSnapshot(input.SnapshotJSON)
	if err != nil {
		return nil, err
	}

	output := &Output{HasIssue: false}

	if snap.Error != "" {
		return output, nil
	}

	if input.Baseline == nil {
		output.BaselineUpdate = &model.MonitorBaselineUpdate{
			ContentHash:       snap.ContentHash,
			DomStructureHash:  fmt.Sprintf("%x", md5.Sum([]byte(extractDOMStructure(snap.RenderedHTML)))),
			Title:             snap.Title,
			StatusCode:        snap.StatusCode,
			VisibleTextLength: len(snap.VisibleText),
			Action:            "init",
		}
		return output, nil
	}

	diffs := a.compareWithBaseline(snap, input.Baseline)
	if len(diffs) > 0 {
		output.HasIssue = true
		output.Severity = classifyTamperSeverity(diffs)
		detailJSON, _ := json.Marshal(map[string]any{
			"diffs":               diffs,
			"title":               snap.Title,
			"status_code":         snap.StatusCode,
			"content_hash":        snap.ContentHash,
			"visible_text_length": len(snap.VisibleText),
		})
		output.DetailsJSON = string(detailJSON)
	}

	return output, nil
}

func (a *TamperAnalyzer) compareWithBaseline(snap *snapshotData, baseline *model.MonitorBaseline) []map[string]any {
	diffs := make([]map[string]any, 0)

	if snap.ContentHash != baseline.ContentHash && baseline.ContentHash != "" {
		diffs = append(diffs, map[string]any{
			"type":     "content_hash",
			"baseline": baseline.ContentHash,
			"current":  snap.ContentHash,
		})
	}

	if snap.Title != baseline.Title && baseline.Title != "" {
		diffs = append(diffs, map[string]any{
			"type":     "title",
			"baseline": baseline.Title,
			"current":  snap.Title,
		})
	}

	if snap.StatusCode != baseline.StatusCode && baseline.StatusCode > 0 {
		diffs = append(diffs, map[string]any{
			"type":     "status_code",
			"baseline": baseline.StatusCode,
			"current":  snap.StatusCode,
		})
	}

	if baseline.VisibleTextLength > 0 {
		diff := len(snap.VisibleText) - baseline.VisibleTextLength
		ratio := float64(absInt(diff)) / float64(baseline.VisibleTextLength)
		if ratio > 0.3 {
			diffs = append(diffs, map[string]any{
				"type":     "text_length",
				"baseline": baseline.VisibleTextLength,
				"current":  len(snap.VisibleText),
				"ratio":    ratio,
			})
		}
	}

	injected := a.checkInjectedElements(snap)
	if len(injected) > 0 {
		diffs = append(diffs, map[string]any{
			"type":     "injected_elements",
			"elements": injected,
		})
	}

	return diffs
}

func (a *TamperAnalyzer) checkInjectedElements(snap *snapshotData) []map[string]any {
	findings := make([]map[string]any, 0)
	trustedCDNs := a.loadTrustedDomains()

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

func (a *TamperAnalyzer) loadTrustedDomains() []string {
	if a.rules == nil {
		return nil
	}
	data, err := a.rules.GetModuleRules("tamper")
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

func classifyTamperSeverity(diffs []map[string]any) string {
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
