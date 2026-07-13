package traffic

import (
	"testing"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestAssetServiceCreateValidatesAndNormalizes(t *testing.T) {
	svc := NewAssetService(store.NewMemoryStore())
	a, err := svc.Create(domain.Asset{Name: "web", AssetType: "IP资产", Address: "  10.0.0.9 "})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.AssetType != "ip" {
		t.Fatalf("type alias not normalized: %q", a.AssetType)
	}
	if a.Address != "10.0.0.9" {
		t.Fatalf("address not normalized: %q", a.Address)
	}
	// 缺 name
	if _, err := svc.Create(domain.Asset{AssetType: "ip", Address: "1.1.1.1"}); err == nil {
		t.Fatal("expected name required error")
	}
	// 非法 ip
	if _, err := svc.Create(domain.Asset{Name: "x", AssetType: "ip", Address: "not-an-ip"}); err == nil {
		t.Fatal("expected invalid ip error")
	}
}

func TestAssetServiceSegmentCreate(t *testing.T) {
	svc := NewAssetService(store.NewMemoryStore())

	// 标准 CIDR：类型别名归一化 + 地址规范化
	a, err := svc.Create(domain.Asset{Name: "出口段", AssetType: "网段资产", Address: " 192.168.10.0/24 "})
	if err != nil {
		t.Fatalf("create cidr: %v", err)
	}
	if a.AssetType != "ip_segment" {
		t.Fatalf("type alias not normalized: %q", a.AssetType)
	}
	if a.Address != "192.168.10.0/24" {
		t.Fatalf("address = %q, want 192.168.10.0/24", a.Address)
	}

	// 点分掩码 → 规范 CIDR（并取整到网络基址）
	b, err := svc.Create(domain.Asset{Name: "服务器段", AssetType: "网段", Address: "36.154.169.2/255.255.255.224"})
	if err != nil {
		t.Fatalf("create dotted mask: %v", err)
	}
	if b.Address != "36.154.169.0/27" {
		t.Fatalf("address = %q, want 36.154.169.0/27", b.Address)
	}

	// 非网络基址的 CIDR 也取整到基址
	c, err := svc.Create(domain.Asset{Name: "细分段", AssetType: "cidr", Address: "10.1.2.200/25"})
	if err != nil {
		t.Fatalf("create non-base cidr: %v", err)
	}
	if c.Address != "10.1.2.128/25" {
		t.Fatalf("address = %q, want 10.1.2.128/25", c.Address)
	}

	// 非法网段
	for _, bad := range []string{"10.0.0.1", "10.0.0.0/33", "10.0.0.0/255.255.0.1", "abc/24"} {
		if _, err := svc.Create(domain.Asset{Name: "x", AssetType: "ip_segment", Address: bad}); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}

	// 更新地址（patch 不带类型）也按网段归一化，"/" 不被截断
	up, ok, err := svc.Update(a.ID, map[string]any{"address": "58.218.177.128/27"})
	if err != nil || !ok {
		t.Fatalf("update: ok=%v err=%v", ok, err)
	}
	if up.Address != "58.218.177.128/27" {
		t.Fatalf("updated address = %q", up.Address)
	}
}

func TestAssetServiceImportSegmentCSV(t *testing.T) {
	svc := NewAssetService(store.NewMemoryStore())
	csv := "资产名称,资产类型,地址,所属单位,责任人,备注\n" +
		"网段A,网段资产,222.187.92.0/24,大数据中心服务器,,\n" +
		"网段B,网段,36.154.169.2/255.255.255.224,大数据中心服务器,,\n" +
		"坏网段,网段资产,1.2.3.4,,,\n" // 单 IP 不是网段 → 错误
	imported, errs := svc.Import("segments.csv", []byte(csv))
	if imported != 2 {
		t.Fatalf("imported=%d want 2, errs=%+v", imported, errs)
	}
	if len(errs) != 1 || errs[0].Row != 4 {
		t.Fatalf("expected 1 error at row 4, got %+v", errs)
	}
	list := svc.List()
	if len(list) != 2 {
		t.Fatalf("list want 2 got %d", len(list))
	}
	for _, a := range list {
		if a.AssetType != "ip_segment" {
			t.Fatalf("asset type = %q", a.AssetType)
		}
	}
}

func TestAssetServiceImportCSV(t *testing.T) {
	svc := NewAssetService(store.NewMemoryStore())
	csv := "资产名称,资产类型,地址,所属单位,责任人,备注\n" +
		"网站A,域名网站,example.com,单位甲,张三,备注1\n" +
		"主机B,IP资产,10.0.0.5,单位乙,李四,\n" +
		",IP资产,1.2.3.4,,,\n" // 第3行缺名称 → 错误
	imported, errs := svc.Import("assets.csv", []byte(csv))
	if imported != 2 {
		t.Fatalf("imported=%d want 2", imported)
	}
	if len(errs) != 1 || errs[0].Row != 4 {
		t.Fatalf("expected 1 error at row 4, got %+v", errs)
	}
	if len(svc.List()) != 2 {
		t.Fatalf("list want 2 got %d", len(svc.List()))
	}
}
