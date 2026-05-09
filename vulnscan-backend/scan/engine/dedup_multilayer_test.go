package engine

import (
	"testing"
)

func TestBloomFilter_AddAndTest(t *testing.T) {
	bf := NewBloomFilter(1000, 0.01)

	bf.Add("test1")
	if !bf.Test("test1") {
		t.Error("添加后应能检测到")
	}

	if bf.Test("nonexistent") {
		t.Log("可能存在误判，但在预期范围内")
	}
}

func TestBloomFilter_MultipleAdds(t *testing.T) {
	bf := NewBloomFilter(10000, 0.01)

	items := []string{"item1", "item2", "item3", "item4", "item5"}
	for _, item := range items {
		bf.Add(item)
	}

	for _, item := range items {
		if !bf.Test(item) {
			t.Errorf("添加的 %s 应能检测到", item)
		}
	}
}

func TestMultiLayerDedup_FirstNotDuplicate(t *testing.T) {
	d := NewMultiLayerDeduplicator(1000, 0.01, false, nil)
	f := &Finding{
		ModuleID: "test_mod",
		Target:   &Target{Host: "example.com", IP: "1.1.1.1", Port: 80},
		Type:     "vuln",
		Title:    "SQLi",
	}

	if d.IsDuplicate("task1", f) {
		t.Error("第一次不应判定为重复")
	}
}

func TestMultiLayerDedup_SecondDuplicate(t *testing.T) {
	d := NewMultiLayerDeduplicator(1000, 0.01, false, nil)
	f := &Finding{
		ModuleID: "test_mod",
		Target:   &Target{Host: "example.com", IP: "1.1.1.1", Port: 80},
		Type:     "vuln",
		Title:    "SQLi",
	}

	d.IsDuplicate("task1", f)
	if !d.IsDuplicate("task1", f) {
		t.Error("第二次同任务同发现应判定为重复")
	}
}

func TestMultiLayerDedup_DifferentTaskNotDuplicate(t *testing.T) {
	d := NewMultiLayerDeduplicator(1000, 0.01, false, nil)
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

func TestMultiLayerDedup_CrossTaskDuplicate(t *testing.T) {
	d := NewMultiLayerDeduplicator(1000, 0.01, true, nil)
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

func TestMultiLayerDedup_DeduplicateFindings(t *testing.T) {
	d := NewMultiLayerDeduplicator(1000, 0.01, false, nil)

	findings := []*Finding{
		{ModuleID: "m1", Target: &Target{Host: "a.com", Port: 80}, Type: "vuln", Title: "SQL Injection"},
		{ModuleID: "m1", Target: &Target{Host: "a.com", Port: 80}, Type: "vuln", Title: "SQL Injection"},
		{ModuleID: "m1", Target: &Target{Host: "b.com", Port: 80}, Type: "vuln", Title: "SQL Injection"},
	}

	unique := d.DeduplicateFindings("task1", findings)
	if len(unique) != 2 {
		t.Errorf("去重后应为 2 条, got %d", len(unique))
	}
}

func TestMultiLayerDedup_Count(t *testing.T) {
	d := NewMultiLayerDeduplicator(1000, 0.01, false, nil)
	if d.Count() != 0 {
		t.Error("初始计数应为 0")
	}

	d.IsDuplicate("t1", &Finding{ModuleID: "m", Target: &Target{Host: "a"}, Type: "v", Title: "1"})
	d.IsDuplicate("t1", &Finding{ModuleID: "m", Target: &Target{Host: "b"}, Type: "v", Title: "2"})

	if d.Count() != 2 {
		t.Errorf("应有 2 条指纹, got %d", d.Count())
	}
}

func TestMultiLayerDedup_Reset(t *testing.T) {
	d := NewMultiLayerDeduplicator(1000, 0.01, false, nil)
	d.IsDuplicate("t1", &Finding{ModuleID: "m", Target: &Target{}, Type: "v", Title: "1"})
	d.Reset()

	if d.Count() != 0 {
		t.Error("重置后计数应为 0")
	}
}

func TestMultiLayerDedup_NilTarget(t *testing.T) {
	d := NewMultiLayerDeduplicator(1000, 0.01, false, nil)
	f := &Finding{ModuleID: "m", Target: nil, Type: "v", Title: "no-target"}

	if d.IsDuplicate("t1", f) {
		t.Error("nil target 不应 panic 且第一次不应判定为重复")
	}
}
