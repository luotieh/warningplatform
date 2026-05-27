package analyzer

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
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

	if len(blacklinks) > 0 || len(backdoorFindings) > 0 {
		output.HasIssue = true
		output.Severity = classifyBlacklinkSeverity(blacklinks, backdoorFindings)
		detailJSON, _ := json.Marshal(map[string]any{
			"blacklink_matches": blacklinks,
			"backdoor_findings": backdoorFindings,
			"total_links":       len(snap.Links),
			"external_links":    countExternalLinks(snap.Links),
		})
		output.DetailsJSON = string(detailJSON)
	}

	return output, nil
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
