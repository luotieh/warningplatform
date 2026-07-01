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
