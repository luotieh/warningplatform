package scanrunner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"vulnscan-backend/model"
	"vulnscan-backend/scan/core"
)

type FindingFilter struct {
	exclusions []model.ScanExclusion
	fpRules    []model.FPRule
	hitExcl    map[string]struct{}
	hitFP      map[string]struct{}
}

func NewFindingFilter(exclusions []model.ScanExclusion, fpRules []model.FPRule) *FindingFilter {
	return &FindingFilter{
		exclusions: exclusions,
		fpRules:    fpRules,
		hitExcl:    make(map[string]struct{}),
		hitFP:      make(map[string]struct{}),
	}
}

func (f *FindingFilter) ShouldExcludeTarget(target string, port int) bool {
	for _, rule := range f.exclusions {
		switch rule.RuleType {
		case model.ExclusionRuleTypeTarget:
			if matchWildcard(rule.MatchValue, target) {
				f.hitExcl[rule.ID] = struct{}{}
				return true
			}
		case model.ExclusionRuleTypePort:
			if rule.MatchValue == strconv.Itoa(port) {
				f.hitExcl[rule.ID] = struct{}{}
				return true
			}
		}
	}
	return false
}

func (f *FindingFilter) ShouldSuppressFinding(finding *core.Finding) bool {
	target := ""
	port := 0
	if finding.Target != nil {
		target = finding.Target.Host
		if target == "" {
			target = finding.Target.IP
		}
		port = finding.Target.Port
	}

	for _, rule := range f.exclusions {
		switch rule.RuleType {
		case model.ExclusionRuleTypeTarget:
			if matchWildcard(rule.MatchValue, target) {
				f.hitExcl[rule.ID] = struct{}{}
				return true
			}
		case model.ExclusionRuleTypePort:
			if rule.MatchValue == strconv.Itoa(port) {
				f.hitExcl[rule.ID] = struct{}{}
				return true
			}
		case model.ExclusionRuleTypePath:
			if finding.Target != nil && finding.Target.URL != "" {
				if matchWildcard(rule.MatchValue, finding.Target.URL) {
					f.hitExcl[rule.ID] = struct{}{}
					return true
				}
			}
		case model.ExclusionRuleTypeModule:
			if rule.MatchValue == finding.ModuleID {
				f.hitExcl[rule.ID] = struct{}{}
				return true
			}
		case model.ExclusionRuleTypeFindingType:
			if rule.MatchValue == finding.Type {
				f.hitExcl[rule.ID] = struct{}{}
				return true
			}
		}
	}

	for _, rule := range f.fpRules {
		switch rule.MatchType {
		case model.FPMatchTypeFingerprint:
			fp := fmt.Sprintf("%s:%d:%s:%s", target, port, finding.ModuleID, finding.Type)
			if rule.MatchValue == fp {
				f.hitFP[rule.ID] = struct{}{}
				return true
			}
		case model.FPMatchTypeModuleType:
			mt := fmt.Sprintf("%s:%s", finding.ModuleID, finding.Type)
			if rule.MatchValue == mt {
				f.hitFP[rule.ID] = struct{}{}
				return true
			}
		case model.FPMatchTypeTitlePattern:
			if matchPattern(rule.MatchValue, finding.Title) {
				f.hitFP[rule.ID] = struct{}{}
				return true
			}
		case model.FPMatchTypeTargetType:
			if matchWildcard(rule.MatchValue, target) {
				f.hitFP[rule.ID] = struct{}{}
				return true
			}
		}
	}

	return false
}

func (f *FindingFilter) FilterFindings(findings []*core.Finding) []*core.Finding {
	if len(f.exclusions) == 0 && len(f.fpRules) == 0 {
		return findings
	}

	result := make([]*core.Finding, 0, len(findings))
	for _, finding := range findings {
		if !f.ShouldSuppressFinding(finding) {
			result = append(result, finding)
		}
	}
	return result
}

func (f *FindingFilter) HitExclusionIDs() []string {
	ids := make([]string, 0, len(f.hitExcl))
	for id := range f.hitExcl {
		ids = append(ids, id)
	}
	return ids
}

func (f *FindingFilter) HitFPRuleIDs() []string {
	ids := make([]string, 0, len(f.hitFP))
	for id := range f.hitFP {
		ids = append(ids, id)
	}
	return ids
}

func matchWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(pattern, value)
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 2 {
		prefix := strings.ToLower(parts[0])
		suffix := strings.ToLower(parts[1])
		lower := strings.ToLower(value)
		return strings.HasPrefix(lower, prefix) && strings.HasSuffix(lower, suffix)
	}
	regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")
	re, err := regexp.Compile("(?i)" + regexPattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func matchPattern(pattern, value string) bool {
	if pattern == value {
		return true
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
	}
	return re.MatchString(value)
}
