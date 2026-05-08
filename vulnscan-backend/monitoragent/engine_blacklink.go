package monitoragent

import (
	"context"
	"encoding/json"
	"strings"
)

type BlacklinkEngine struct {
	Rules RuleStore
}

func (e *BlacklinkEngine) Name() string { return "blacklink" }

func (e *BlacklinkEngine) Run(ctx context.Context, task *TaskMessage, snap *PageSnapshot) (map[string]any, error) {
	result := map[string]any{
		"url":       task.URL,
		"has_black": false,
	}

	if snap == nil || snap.Error != "" {
		return result, nil
	}

	pageDomain := extractHost(task.URL)

	blackPatterns := e.loadBlackPatterns()
	backdoorPaths := e.loadBackdoorPaths()

	var blacklinks []map[string]any

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

	var backdoorFindings []map[string]any
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

	result["blacklink_matches"] = blacklinks
	result["backdoor_findings"] = backdoorFindings
	result["total_links"] = len(snap.Links)
	result["external_links"] = countExternal(snap.Links)

	if len(blacklinks) > 0 || len(backdoorFindings) > 0 {
		result["has_black"] = true
	}

	return result, nil
}

func (e *BlacklinkEngine) loadBlackPatterns() []string {
	if e.Rules == nil {
		return nil
	}
	data, err := e.Rules.GetModuleRules("engine/blacklink")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		BlackPatterns []string `json:"black_patterns"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return cfg.BlackPatterns
}

func (e *BlacklinkEngine) loadBackdoorPaths() []string {
	if e.Rules == nil {
		return nil
	}
	data, err := e.Rules.GetModuleRules("engine/blacklink")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		BackdoorPaths []string `json:"backdoor_paths"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return cfg.BackdoorPaths
}

func countExternal(links []LinkInfo) int {
	count := 0
	for _, l := range links {
		if l.IsExternal {
			count++
		}
	}
	return count
}
