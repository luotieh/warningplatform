package scanrunner

import (
	"strings"

	"code.yt-security.com/public/scanengine/core"
	"vulnscan-backend/model"
)

// EnginePolicy 从任务 Parameters / Config 解析（支持嵌套 map "engine" 与顶层键）。
// 未配置项保持零值，表示「不启用/使用 Runner 默认」。
type EnginePolicy struct {
	MaxFindingsPersisted  int
	MinConfidence         int
	MinConfidenceVulnOnly bool
	RequireVulnEvidence   bool
	StrictDedup           bool

	AutoSkipWebVulnsWithoutHTTP bool

	CircuitFailThreshold int
	CircuitResetSeconds  int

	AdaptiveMinConcurrency int
	AdaptiveMaxConcurrency int

	CacheMaxEntries int
	CacheTTLSeconds int

	ModuleTimeoutSeconds int

	HostRateLimitRPS   int
	HostRateLimitBurst int

	RejectPrincipleScan bool // true: reject vuln findings that are principle-only (no exploit verification)
	RequireVerified     bool // true: only persist findings with Verified=true
}

func mergeTaskConfigSource(task model.ScanTask) map[string]interface{} {
	src := buildConfig(task)
	if task.Config != nil {
		for k, v := range task.Config {
			if _, ok := src[k]; !ok {
				src[k] = v
			}
		}
	}
	return src
}

// ParseEnginePolicy 从任务配置解析引擎策略。
func ParseEnginePolicy(src map[string]interface{}) EnginePolicy {
	p := EnginePolicy{
		AutoSkipWebVulnsWithoutHTTP: true,
		RejectPrincipleScan:         true,
		RequireVulnEvidence:         true,
	}
	if len(src) == 0 {
		return p
	}
	if sub, ok := src["engine"].(map[string]interface{}); ok {
		applyEngineMap(&p, sub)
	}
	applyEngineMap(&p, src)
	return p
}

func applyEngineMap(p *EnginePolicy, m map[string]interface{}) {
	if m == nil {
		return
	}
	if v, ok := intFromAny(m["max_findings"]); ok && v > 0 {
		p.MaxFindingsPersisted = v
	}
	if v, ok := intFromAny(m["engine.max_findings"]); ok && v > 0 {
		p.MaxFindingsPersisted = v
	}
	if v, ok := intFromAny(m["min_confidence"]); ok && v > 0 {
		p.MinConfidence = v
	}
	if v, ok := intFromAny(m["engine.min_confidence"]); ok && v > 0 {
		p.MinConfidence = v
	}
	if b, ok := boolFromAny(m["engine.min_confidence_vuln_only"]); ok {
		p.MinConfidenceVulnOnly = b
	}
	if b, ok := boolFromAny(m["engine.require_vuln_evidence"]); ok {
		p.RequireVulnEvidence = b
	}
	if b, ok := boolFromAny(m["strict_dedup"]); ok {
		p.StrictDedup = b
	}
	if b, ok := boolFromAny(m["engine.strict_dedup"]); ok {
		p.StrictDedup = b
	}
	if b, ok := boolFromAny(m["auto_skip_web_vulns_without_http"]); ok {
		p.AutoSkipWebVulnsWithoutHTTP = b
	}
	if b, ok := boolFromAny(m["engine.auto_skip_web_vulns_without_http"]); ok {
		p.AutoSkipWebVulnsWithoutHTTP = b
	}
	if v, ok := intFromAny(m["engine.circuit_fail_threshold"]); ok && v > 0 {
		p.CircuitFailThreshold = v
	}
	if v, ok := intFromAny(m["engine.circuit_reset_seconds"]); ok && v > 0 {
		p.CircuitResetSeconds = v
	}
	if v, ok := intFromAny(m["engine.adaptive_min_concurrency"]); ok && v >= 1 {
		p.AdaptiveMinConcurrency = v
	}
	if v, ok := intFromAny(m["engine.adaptive_max_concurrency"]); ok && v >= 1 {
		p.AdaptiveMaxConcurrency = v
	}
	if v, ok := intFromAny(m["engine.cache_max_entries"]); ok && v > 0 {
		p.CacheMaxEntries = v
	}
	if v, ok := intFromAny(m["engine.cache_ttl_seconds"]); ok && v > 0 {
		p.CacheTTLSeconds = v
	}
	if v, ok := intFromAny(m["engine.module_timeout_seconds"]); ok && v > 0 {
		p.ModuleTimeoutSeconds = v
	}
	if v, ok := intFromAny(m["host_rate_limit"]); ok && v > 0 {
		p.HostRateLimitRPS = v
	}
	if v, ok := intFromAny(m["engine.host_rate_limit"]); ok && v > 0 {
		p.HostRateLimitRPS = v
	}
	if v, ok := intFromAny(m["engine.host_rate_burst"]); ok && v > 0 {
		p.HostRateLimitBurst = v
	}
	if b, ok := boolFromAny(m["engine.reject_principle_scan"]); ok {
		p.RejectPrincipleScan = b
	}
	if b, ok := boolFromAny(m["reject_principle_scan"]); ok {
		p.RejectPrincipleScan = b
	}
	if b, ok := boolFromAny(m["engine.require_verified"]); ok {
		p.RequireVerified = b
	}
	if b, ok := boolFromAny(m["require_verified"]); ok {
		p.RequireVerified = b
	}
}

func intFromAny(v interface{}) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int32:
		return int(t), true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	default:
		return 0, false
	}
}

func boolFromAny(v interface{}) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		if s == "false" || s == "0" || s == "no" {
			return false, true
		}
		return s == "true" || s == "1" || s == "yes", true
	default:
		return false, false
	}
}

// AllowPersistFinding 持久化前的质量门（不含 max_findings 计数，由 Runner 计数）。
func (p EnginePolicy) AllowPersistFinding(f *core.Finding) bool {
	if f == nil {
		return false
	}
	cat := model.InferFindingCategory(f.ModuleID, f.Type)

	if p.MinConfidence > 0 && f.Confidence > 0 && f.Confidence < p.MinConfidence {
		if p.MinConfidenceVulnOnly && cat != model.FindingCategoryVuln {
			return true
		}
		if !p.MinConfidenceVulnOnly || cat == model.FindingCategoryVuln {
			return false
		}
	}

	if p.RequireVulnEvidence && cat == model.FindingCategoryVuln {
		if strings.TrimSpace(f.Evidence) == "" && len(strings.TrimSpace(f.Description)) < 24 && len(f.Data) == 0 {
			return false
		}
	}

	if cat == model.FindingCategoryVuln {
		if p.RejectPrincipleScan && f.VerificationLevel == core.VerifyPrinciple && !f.Verified {
			return false
		}
		if p.RequireVerified && !f.Verified {
			return false
		}
	}

	return true
}
