package analyzer

import (
	"context"
	"encoding/json"
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
	blackPatterns := a.loadBlackPatterns()
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

		for _, pat := range blackPatterns {
			if strings.Contains(strings.ToLower(link.URL), strings.ToLower(pat)) {
				isBlack = true
				matchedPattern = pat
				break
			}
		}

		if link.IsHidden {
			isBlack = true
			matchedPattern = "hidden_link"
		}

		if isBlack {
			blacklinks = append(blacklinks, map[string]any{
				"url":     link.URL,
				"domain":  linkDomain,
				"hidden":  link.IsHidden,
				"pattern": matchedPattern,
			})
		}
	}

	backdoorFindings := make([]map[string]any, 0)
	for _, path := range backdoorPaths {
		for _, script := range snap.Scripts {
			if strings.Contains(strings.ToLower(script.Src), strings.ToLower(path)) {
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

func (a *BlacklinkAnalyzer) loadBlackPatterns() []string {
	if a.rules == nil {
		return nil
	}
	data, err := a.rules.GetModuleRules("blacklink")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		Rules []struct {
			Re   string `json:"re"`
			Mark string `json:"mark"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	patterns := make([]string, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		if r.Re != "" {
			patterns = append(patterns, strings.TrimPrefix(strings.TrimPrefix(r.Re, "(?i)"), ""))
		}
	}
	return patterns
}

func (a *BlacklinkAnalyzer) loadBackdoorPaths() []string {
	if a.rules == nil {
		return nil
	}
	data, err := a.rules.GetModuleRules("backdoor_path")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		Entries []struct {
			Path string `json:"path"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	paths := make([]string, 0, len(cfg.Entries))
	for _, e := range cfg.Entries {
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
