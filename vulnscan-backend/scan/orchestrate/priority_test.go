package orchestrate

import (
	"vulnscan-backend/scan/core"

	"context"
	"testing"
)

type stubModule struct {
	id string
}

func (s *stubModule) ID() string       { return s.id }
func (s *stubModule) Name() string     { return s.id }
func (s *stubModule) Category() string { return "test" }
func (s *stubModule) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	return &core.ModuleResult{}, nil
}

func TestPrioritizer_EmptyNoChange(t *testing.T) {
	mp := NewModulePrioritizer()
	mods := []core.ScanModule{&stubModule{"a"}, &stubModule{"b"}}

	sorted := mp.SortModules(mods)
	if len(sorted) != 2 {
		t.Fatalf("应返回 2 个模块, got %d", len(sorted))
	}
	if sorted[0].ID() != "a" || sorted[1].ID() != "b" {
		t.Error("无历史数据时顺序不应改变")
	}
}

func TestPrioritizer_HighFindingsFirst(t *testing.T) {
	mp := NewModulePrioritizer()

	mp.RecordResult("slow_mod", 1, 0, 5000, true)
	mp.RecordResult("fast_mod", 10, 5, 100, true)

	mods := []core.ScanModule{&stubModule{"slow_mod"}, &stubModule{"fast_mod"}}
	sorted := mp.SortModules(mods)

	if sorted[0].ID() != "fast_mod" {
		t.Errorf("发现多+目标多+速度快的模块应排在前面, got %s", sorted[0].ID())
	}
}

func TestPrioritizer_FailurePenalty(t *testing.T) {
	mp := NewModulePrioritizer()

	mp.RecordResult("reliable_mod", 5, 2, 200, true)
	mp.RecordResult("reliable_mod", 5, 2, 200, true)

	mp.RecordResult("flaky_mod", 5, 2, 200, true)
	mp.RecordResult("flaky_mod", 0, 0, 200, false)
	mp.RecordResult("flaky_mod", 0, 0, 200, false)

	mods := []core.ScanModule{&stubModule{"flaky_mod"}, &stubModule{"reliable_mod"}}
	sorted := mp.SortModules(mods)

	if sorted[0].ID() != "reliable_mod" {
		t.Errorf("稳定模块应排在前面, got %s", sorted[0].ID())
	}
}

func TestPrioritizer_UnknownModuleGetsZero(t *testing.T) {
	mp := NewModulePrioritizer()
	mp.RecordResult("known", 5, 0, 100, true)

	score := mp.getScore("unknown")
	if score != 0 {
		t.Errorf("未知模块分数应为 0, got %f", score)
	}
}

func TestPrioritizer_Stats(t *testing.T) {
	mp := NewModulePrioritizer()
	mp.RecordResult("mod1", 10, 3, 150, true)

	stats := mp.Stats()
	modStats, ok := stats["mod1"].(map[string]interface{})
	if !ok {
		t.Fatal("mod1 统计不存在")
	}
	if modStats["findings"].(int) != 10 {
		t.Errorf("发现数应为 10, got %v", modStats["findings"])
	}
	if modStats["targets"].(int) != 3 {
		t.Errorf("目标数应为 3, got %v", modStats["targets"])
	}
}

func TestPrioritizer_MultipleRecords(t *testing.T) {
	mp := NewModulePrioritizer()

	for i := 0; i < 10; i++ {
		mp.RecordResult("mod1", 1, 0, 100, true)
	}
	for i := 0; i < 3; i++ {
		mp.RecordResult("mod2", 1, 0, 100, true)
	}

	mods := []core.ScanModule{&stubModule{"mod2"}, &stubModule{"mod1"}}
	sorted := mp.SortModules(mods)
	if sorted[0].ID() != "mod1" {
		t.Errorf("累计发现多的模块应排在前面, got %s", sorted[0].ID())
	}
}
