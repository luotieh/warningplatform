package engine

import (
	"testing"
	"time"
)

func TestDedup_SameTaskSameFinding(t *testing.T) {
	d := NewFindingDeduplicator(false)
	f := &Finding{
		ModuleID: "test_mod",
		Target:   &Target{Host: "example.com", IP: "1.1.1.1", Port: 80},
		Type:     "vuln",
		Title:    "SQLi",
	}

	if d.IsDuplicate("task1", f) {
		t.Error("第一次不应判定为重复")
	}
	if !d.IsDuplicate("task1", f) {
		t.Error("第二次同任务同发现应判定为重复")
	}
}

func TestDedup_DifferentTaskNotDuplicate(t *testing.T) {
	d := NewFindingDeduplicator(false)
	f := &Finding{
		ModuleID: "test_mod",
		Target:   &Target{Host: "example.com", Port: 80},
		Type:     "vuln",
		Title:    "XSS",
	}

	d.IsDuplicate("task1", f)
	if d.IsDuplicate("task2", f) {
		t.Error("不同任务的同一发现在非跨任务模式下不应判定为重复")
	}
}

func TestDedup_CrossTaskDuplicate(t *testing.T) {
	d := NewFindingDeduplicator(true)
	f := &Finding{
		ModuleID: "test_mod",
		Target:   &Target{Host: "example.com", Port: 80},
		Type:     "vuln",
		Title:    "XSS",
	}

	d.IsDuplicate("task1", f)
	if !d.IsDuplicate("task2", f) {
		t.Error("跨任务模式下同一发现应判定为重复")
	}
}

func TestDedup_DeduplicateFindings(t *testing.T) {
	d := NewFindingDeduplicator(false)
	now := time.Now()

	findings := []*Finding{
		{ModuleID: "m1", Target: &Target{Host: "a.com", Port: 80}, Type: "vuln", Title: "SQL Injection", Timestamp: now},
		{ModuleID: "m1", Target: &Target{Host: "a.com", Port: 80}, Type: "vuln", Title: "SQL Injection", Timestamp: now},
		{ModuleID: "m1", Target: &Target{Host: "b.com", Port: 80}, Type: "vuln", Title: "SQL Injection", Timestamp: now},
	}

	unique := d.DeduplicateFindings("task1", findings)
	if len(unique) != 2 {
		t.Errorf("去重后应为 2 条, got %d", len(unique))
	}
}

func TestDedup_Count(t *testing.T) {
	d := NewFindingDeduplicator(false)
	if d.Count() != 0 {
		t.Error("初始计数应为 0")
	}

	d.IsDuplicate("t1", &Finding{ModuleID: "m", Target: &Target{Host: "a"}, Type: "v", Title: "1"})
	d.IsDuplicate("t1", &Finding{ModuleID: "m", Target: &Target{Host: "b"}, Type: "v", Title: "2"})

	if d.Count() != 2 {
		t.Errorf("应有 2 条指纹, got %d", d.Count())
	}
}

func TestDedup_Reset(t *testing.T) {
	d := NewFindingDeduplicator(false)
	d.IsDuplicate("t1", &Finding{ModuleID: "m", Target: &Target{}, Type: "v", Title: "1"})
	d.Reset()

	if d.Count() != 0 {
		t.Error("重置后计数应为 0")
	}
}

func TestDedup_NilTarget(t *testing.T) {
	d := NewFindingDeduplicator(false)
	f := &Finding{ModuleID: "m", Target: nil, Type: "v", Title: "no-target"}

	if d.IsDuplicate("t1", f) {
		t.Error("nil target 不应 panic 且第一次不应判定为重复")
	}
}
