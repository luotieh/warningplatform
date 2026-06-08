package orchestrate

import (
	"code.yt-security.com/public/scanengine/core"

	"testing"
)

func TestTargetPropagator_Propagate(t *testing.T) {
	propagator := NewSmartTargetPropagator()

	existing := []*core.Target{
		{Host: "example.com", Port: 80},
	}

	newTargets := []*core.Target{
		{Host: "example.com", Port: 443},
		{Host: "api.example.com", Port: 80},
	}

	findings := []*core.Finding{
		{
			Target:   &core.Target{Host: "example.com", Port: 80},
			Type:     "vulnerability",
			Severity: "high",
			Title:    "SQL Injection",
		},
	}

	result := propagator.Propagate(existing, newTargets, findings)

	if len(result) == 0 {
		t.Error("传播后应有目标")
	}
}

func TestTargetDeduplicator_SmartDedup(t *testing.T) {
	dedup := NewTargetDeduplicator()

	targets := []*core.Target{
		{Host: "example.com", Port: 80},
		{Host: "example.com", Port: 80},
		{Host: "api.example.com", Port: 443},
	}

	result := dedup.SmartDedup(targets)

	if len(result) < 2 {
		t.Errorf("去重后应至少 2 个目标, got %d", len(result))
	}
}

func TestTargetDeduplicator_MergeWildcards(t *testing.T) {
	dedup := NewTargetDeduplicator()

	targets := []*core.Target{
		{Host: "*.example.com", Port: 80},
		{Host: "example.com", Port: 80},
	}

	result := dedup.mergeWildcards(targets)

	if len(result) != 1 {
		t.Errorf("泛域名合并后应为 1 个目标, got %d", len(result))
	}
}

func TestTargetPrioritizer_SortByRisk(t *testing.T) {
	prioritizer := NewTargetPrioritizer()

	targets := []*core.Target{
		{Host: "low.example.com", Port: 80},
		{Host: "high.example.com", Port: 80},
	}

	findings := []*core.Finding{
		{
			Target:   &core.Target{Host: "high.example.com", Port: 80},
			Type:     "vulnerability",
			Severity: "critical",
			Title:    "RCE",
		},
	}

	result := prioritizer.SortByRisk(targets, findings)

	if len(result) != 2 {
		t.Errorf("排序后应有 2 个目标, got %d", len(result))
	}

	if result[0].Host != "high.example.com" {
		t.Errorf("高危目标应排在前面, got %s", result[0].Host)
	}
}

func TestTargetPrioritizer_BaseScore(t *testing.T) {
	prioritizer := NewTargetPrioritizer()

	targetWithURL := &core.Target{Host: "example.com", Port: 80, URL: "http://example.com"}
	targetWithoutURL := &core.Target{Host: "example.com", Port: 80}

	scoreWithURL := prioritizer.baseScore(targetWithURL)
	scoreWithoutURL := prioritizer.baseScore(targetWithoutURL)

	if scoreWithURL <= scoreWithoutURL {
		t.Error("有 URL 的目标分数应更高")
	}
}

func TestTargetPruner_Prune(t *testing.T) {
	pruner := NewTargetPruner(0.3, 5)

	targets := []*core.Target{
		{Host: "1.example.com"},
		{Host: "2.example.com"},
		{Host: "3.example.com"},
		{Host: "4.example.com"},
		{Host: "5.example.com"},
		{Host: "6.example.com"},
		{Host: "7.example.com"},
	}

	result := pruner.Prune(targets, nil)

	if len(result) > 5 {
		t.Errorf("剪枝后不应超过 5 个目标, got %d", len(result))
	}
}

func TestTargetPropagator_DedupByService(t *testing.T) {
	dedup := NewTargetDeduplicator()

	targets := []*core.Target{
		{Host: "example.com", Port: 80, Service: "http"},
		{Host: "example.com", Port: 80, Service: "http", Product: "nginx"},
	}

	result := dedup.dedupByService(targets)

	if len(result) != 1 {
		t.Errorf("相同服务应合并, got %d", len(result))
	}

	if result[0].Product != "nginx" {
		t.Error("应保留更多信息")
	}
}
