package service

import (
	"strings"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestMatchRegistryAssets(t *testing.T) {
	assets := []domain.Asset{
		{ID: "a1", Name: "内网DNS服务器", AssetType: "ip", Address: "10.0.0.53", Status: 1},
		{ID: "a2", Name: "办公网段", AssetType: "ip_segment", Address: "10.1.0.0/16", Status: 1},
		{ID: "a3", Name: "停用资产", AssetType: "ip", Address: "10.0.0.99", Status: 0},
	}
	if got := matchRegistryAssets(assets, "10.0.0.53"); len(got) != 1 || got[0].Name != "内网DNS服务器" {
		t.Fatalf("exact match=%v", got)
	}
	if got := matchRegistryAssets(assets, "10.1.2.3"); len(got) != 1 || got[0].Name != "办公网段" {
		t.Fatalf("segment match=%v", got)
	}
	if got := matchRegistryAssets(assets, "10.0.0.99"); len(got) != 0 {
		t.Fatalf("disabled asset must be excluded: %v", got)
	}
	if got := matchRegistryAssets(assets, "evil.com"); len(got) != 0 {
		t.Fatalf("domain must not match: %v", got)
	}
	if got := matchRegistryAssets(assets, "8.8.8.8"); len(got) != 0 {
		t.Fatalf("unrelated ip must not match: %v", got)
	}
}

func TestAssetMatchContext(t *testing.T) {
	st := store.NewMemoryStore()
	if _, err := st.CreateAsset(domain.Asset{Name: "内网DNS服务器", AssetType: "ip", Address: "10.0.0.53", Unit: "信息中心", Status: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAsset(domain.Asset{Name: "办公终端网段", AssetType: "ip_segment", Address: "10.1.0.0/16", Status: 1}); err != nil {
		t.Fatal(err)
	}
	svc := Services{Store: st}

	// 威胁侧命中登记资产（DNS 服务器被误标为攻击源的场景）：必须输出复核警示。
	ev := domain.Event{Context: `{"threat_source":"10.0.0.53","victim_target":"10.1.2.3","src_ip":"10.0.0.53","dst_ip":"10.1.2.3"}`}
	out := svc.AssetMatchContext(ev)
	if !strings.Contains(out, "内网DNS服务器") || !strings.Contains(out, "办公终端网段") {
		t.Fatalf("asset names missing: %q", out)
	}
	if !strings.Contains(out, "受害侧") || !strings.Contains(out, "威胁侧") {
		t.Fatalf("roles missing: %q", out)
	}
	if !strings.Contains(out, "复核") {
		t.Fatalf("threat-side registered asset must trigger review warning: %q", out)
	}

	// 无登记资产的事件：地址标注未登记，不输出警示。
	ev2 := domain.Event{Context: `{"threat_source":"8.8.8.8","victim_target":"10.1.2.3"}`}
	out2 := svc.AssetMatchContext(ev2)
	if !strings.Contains(out2, "8.8.8.8（威胁侧）：未登记") || strings.Contains(out2, "复核") {
		t.Fatalf("unregistered threat side: %q", out2)
	}

	// 域名型威胁侧不参与资产匹配。
	ev3 := domain.Event{Context: `{"threat_source":"evil.example.com","victim_target":"10.1.2.3"}`}
	out3 := svc.AssetMatchContext(ev3)
	if strings.Contains(out3, "evil.example.com") {
		t.Fatalf("domain must be skipped: %q", out3)
	}
	if !strings.Contains(out3, "办公终端网段") {
		t.Fatalf("victim segment match missing: %q", out3)
	}
}

func TestAutoAnalysisPromptIncludesAssetSection(t *testing.T) {
	ev := domain.Event{EventID: "e1", EventName: "测试事件", Severity: "high"}
	p := autoAnalysisPrompt(ev, "- 10.1.2.3（受害侧）：办公终端（10.1.2.3）\n")
	if !strings.Contains(p, "资产清单匹配") || !strings.Contains(p, "办公终端（10.1.2.3）") {
		t.Fatalf("asset section missing from prompt: %q", p)
	}
	if !strings.Contains(autoAnalysisPrompt(ev, ""), "无登记信息") {
		t.Fatal("empty asset section must fall back to 无登记信息")
	}
}
