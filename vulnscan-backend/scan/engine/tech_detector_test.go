package engine

import (
	"context"
	"testing"
)

func TestAdvancedTechDetector_DetectFromFingerprints(t *testing.T) {
	detector := NewAdvancedTechDetector()

	targets := []*Target{
		{
			Host: "example.com",
			Port: 80,
			Fingerprints: []Fingerprint{
				{Product: "PHP", Confidence: 80},
				{Product: "WordPress", Confidence: 90},
			},
		},
	}

	profile := detector.Detect(targets, nil)

	if profile.Stack != TechPHP {
		t.Errorf("应检测到 PHP 技术栈, got %s", profile.Stack)
	}
	if profile.Confidence <= 0 {
		t.Error("置信度应大于 0")
	}
	if len(profile.RecommendModules) == 0 {
		t.Error("应有推荐模块")
	}
}

func TestAdvancedTechDetector_DetectFromFindings(t *testing.T) {
	detector := NewAdvancedTechDetector()

	findings := []*Finding{
		{
			Type:        "vulnerability",
			Title:       "Log4j RCE",
			Description: "Apache Log4j remote code execution",
		},
	}

	profile := detector.Detect(nil, findings)

	if profile.Stack != TechJava {
		t.Errorf("应检测到 Java 技术栈, got %s", profile.Stack)
	}
}

func TestAdvancedTechDetector_DetectFromPorts(t *testing.T) {
	detector := NewAdvancedTechDetector()

	targets := []*Target{
		{Host: "db.example.com", Port: 3306},
	}

	profile := detector.Detect(targets, nil)

	if profile.Stack != TechJava {
		t.Errorf("端口 3306 应检测到 Java/MySQL, got %s", profile.Stack)
	}
}

func TestAdvancedTechDetector_UnknownStack(t *testing.T) {
	detector := NewAdvancedTechDetector()

	targets := []*Target{
		{Host: "unknown.example.com", Port: 9999},
	}

	profile := detector.Detect(targets, nil)

	if profile.Stack == TechGeneric {
		t.Log("未识别的技术栈为预期行为")
	}
}

func TestAdvancedTechDetector_EnrichProfile(t *testing.T) {
	detector := NewAdvancedTechDetector()

	targets := []*Target{
		{
			Host:    "example.com",
			Port:    80,
			Service: "nginx",
			Product: "WordPress",
			Version: "6.0",
		},
	}

	profile := detector.Detect(targets, nil)

	if profile.Server != "nginx" {
		t.Errorf("服务器应为 nginx, got %s", profile.Server)
	}
	if profile.Framework != "WordPress" {
		t.Errorf("框架应为 WordPress, got %s", profile.Framework)
	}
	if profile.Version != "6.0" {
		t.Errorf("版本应为 6.0, got %s", profile.Version)
	}
}

func TestSmartModuleCutter_CutModules(t *testing.T) {
	cutter := NewSmartModuleCutter(1.0)

	profile := &AdvancedTechProfile{
		Stack:            TechPHP,
		Confidence:       0.8,
		RecommendModules: []string{"php_rce", "php_sqli"},
		SkipModules:      []string{"java_deserialize"},
		HighPriority:     []string{"wordpress_rce"},
	}

	modules := []ScanModule{
		&techTestModule{id: "php_rce", category: "php"},
		&techTestModule{id: "java_deserialize", category: "java"},
		&techTestModule{id: "common_rce", category: "common"},
	}

	selected := cutter.CutModules(modules, profile, nil)

	if len(selected) == 0 {
		t.Error("应有选中的模块")
	}

	for _, m := range selected {
		if m.ID() == "java_deserialize" {
			t.Error("不应选中 java_deserialize 模块")
		}
	}
}

func TestSmartModuleCutter_ScoreModule(t *testing.T) {
	cutter := NewSmartModuleCutter(1.0)

	profile := &AdvancedTechProfile{
		Stack:      TechJava,
		Confidence: 0.9,
	}

	module := &techTestModule{id: "java_deserialize", category: "java"}
	score := cutter.scoreModule(module, profile, nil)

	if score <= 1.0 {
		t.Errorf("Java 模块在 Java 技术栈下分数应大于 1.0, got %f", score)
	}
}

func TestSmartModuleCutter_UpdateStats(t *testing.T) {
	cutter := NewSmartModuleCutter(1.0)

	cutter.UpdateStats("test_module", true, 100.0)
	cutter.UpdateStats("test_module", true, 150.0)
	cutter.UpdateStats("test_module", false, 200.0)

	stats := cutter.getHistoricalStats("test_module")

	if stats.ExecCount != 3 {
		t.Errorf("执行次数应为 3, got %d", stats.ExecCount)
	}
	if stats.SuccessRate <= 0 || stats.SuccessRate >= 1 {
		t.Errorf("成功率应在 0-1 之间, got %f", stats.SuccessRate)
	}
}

type techTestModule struct {
	id       string
	category string
}

func (m *techTestModule) ID() string {
	return m.id
}

func (m *techTestModule) Name() string {
	return m.id
}

func (m *techTestModule) Category() string {
	return m.category
}

func (m *techTestModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	return &ModuleResult{ModuleID: m.id}, nil
}
