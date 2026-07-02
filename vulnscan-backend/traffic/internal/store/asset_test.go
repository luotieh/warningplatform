package store

import (
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func TestMemoryAssetCRUD(t *testing.T) {
	s := NewMemoryStore()
	a, err := s.CreateAsset(domain.Asset{Name: "web-1", AssetType: "ip", Address: "10.0.0.9", Status: 1})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.ID == "" || a.Status != 1 {
		t.Fatalf("id/status not persisted: %+v", a)
	}
	// 重复 address 冲突
	if _, err := s.CreateAsset(domain.Asset{Name: "web-dup", AssetType: "ip", Address: "10.0.0.9"}); err == nil {
		t.Fatal("expected duplicate address error")
	}
	// list
	if len(s.ListAssets()) != 1 {
		t.Fatalf("list want 1 got %d", len(s.ListAssets()))
	}
	// update
	up, ok := s.UpdateAsset(a.ID, map[string]any{"name": "web-2", "status": 0})
	if !ok || up.Name != "web-2" || up.Status != 0 {
		t.Fatalf("update failed: %+v ok=%v", up, ok)
	}
	// get
	got, ok := s.GetAsset(a.ID)
	if !ok || got.Name != "web-2" {
		t.Fatalf("get failed: %+v", got)
	}
	// delete
	if !s.DeleteAsset(a.ID) || len(s.ListAssets()) != 0 {
		t.Fatal("delete failed")
	}
	// store 不强制默认：显式 status=0（停用）应原样保留
	z, err := s.CreateAsset(domain.Asset{Name: "z", AssetType: "ip", Address: "10.0.0.10", Status: 0})
	if err != nil {
		t.Fatalf("create z: %v", err)
	}
	if z.Status != 0 {
		t.Fatalf("store must not coerce status: %+v", z)
	}
}
