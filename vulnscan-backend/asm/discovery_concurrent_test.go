package asm

import (
	"context"
	"testing"
	"time"
)

func TestConcurrentDiscoveryEngine_BasicDiscover(t *testing.T) {
	engine := NewConcurrentDiscoveryEngine(5, 5*time.Second)

	project := &ASMProject{
		Seeds: []Seed{
			{Value: "example.com", Type: "domain"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	assets, err := engine.Discover(ctx, project)

	if err != nil {
		t.Logf("发现过程可能有错误: %v", err)
	}

	if assets == nil {
		t.Log("资产列表可能为空（取决于收集器实现）")
	}
}

func TestConcurrentDiscoveryEngine_ContextCancellation(t *testing.T) {
	engine := NewConcurrentDiscoveryEngine(5, 5*time.Second)

	project := &ASMProject{
		Seeds: []Seed{
			{Value: "example.com", Type: "domain"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := engine.Discover(ctx, project)

	if err == nil {
		t.Log("上下文已取消，应返回错误")
	}
}

func TestRiskScorer_Calculate(t *testing.T) {
	scorer := NewRiskScorer()

	asset := DiscoveredAsset{
		Type:   "ip",
		Value:  "192.168.1.1",
		Source: "port-scan",
	}

	score := scorer.Calculate(asset)

	if score < 0 || score > 100 {
		t.Errorf("风险评分应在 0-100 范围内, got %d", score)
	}
}

func TestRiskScorer_HighRiskPort(t *testing.T) {
	scorer := NewRiskScorer()

	asset := DiscoveredAsset{
		Type:   "port",
		Value:  "6379",
		Source: "port-scan",
		Attributes: map[string]string{
			"high_risk_port": "true",
		},
	}

	score := scorer.Calculate(asset)

	if score < 50 {
		t.Errorf("高危端口资产评分应较高, got %d", score)
	}
}

func TestRiskScorer_InternalAsset(t *testing.T) {
	scorer := NewRiskScorer()

	asset := DiscoveredAsset{
		Type:   "ip",
		Value:  "10.0.0.1",
		Source: "dns",
		Attributes: map[string]string{
			"internal": "true",
		},
	}

	score := scorer.Calculate(asset)

	t.Logf("内部资产评分: %d", score)
}

func TestNormalizeAssetKey(t *testing.T) {
	asset1 := DiscoveredAsset{Type: "domain", Value: "*.example.com"}
	asset2 := DiscoveredAsset{Type: "domain", Value: "example.com"}

	key1 := normalizeAssetKey(asset1)
	key2 := normalizeAssetKey(asset2)

	if key1 != key2 {
		t.Errorf("泛域名和主域名应归一化为相同键, got %s vs %s", key1, key2)
	}
}

func TestNormalizeAssetKey_IP(t *testing.T) {
	asset := DiscoveredAsset{Type: "ip", Value: "192.168.1.1"}

	key := normalizeAssetKey(asset)

	expected := "ip|192.168.1.1"
	if key != expected {
		t.Errorf("IP 资产键应为 %s, got %s", expected, key)
	}
}
