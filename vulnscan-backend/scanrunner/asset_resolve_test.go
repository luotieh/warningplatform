package scanrunner

import (
	"testing"

	"vulnscan-backend/model"
)

func TestAssetIDResolverSingleAssetEnrich(t *testing.T) {
	task := &model.ScanTask{
		Targets:    []string{"code.yt-security.com"},
		Parameters: model.JSONMap{"asset_id": "asset-1"},
	}
	r := BuildAssetIDResolver(task)
	if got := r.Resolve("hr.code.yt-security.com", 0); got != "asset-1" {
		t.Fatalf("single enrich: got %q want asset-1", got)
	}
}

func TestAssetIDResolverPairedTargets(t *testing.T) {
	task := &model.ScanTask{
		Targets: []string{"a.example.com", "b.example.com"},
		Parameters: model.JSONMap{
			"asset_ids": []interface{}{"id-a", "id-b"},
		},
	}
	r := BuildAssetIDResolver(task)
	if got := r.Resolve("a.example.com", 0); got != "id-a" {
		t.Fatalf("a: got %q", got)
	}
	if got := r.Resolve("b.example.com", 0); got != "id-b" {
		t.Fatalf("b: got %q", got)
	}
	if got := r.Resolve("c.example.com", 0); got != "" {
		t.Fatalf("unknown target should be empty, got %q", got)
	}
}

func TestNormalizeTaskAssetParametersBindings(t *testing.T) {
	params := model.JSONMap{
		"asset_ids": []interface{}{"id-a", "id-b"},
	}
	NormalizeTaskAssetParameters(params, []string{"a.example.com", "b.example.com"})
	raw, ok := params["asset_bindings"].([]map[string]string)
	if !ok {
		t.Fatalf("expected asset_bindings, got %T", params["asset_bindings"])
	}
	if len(raw) != 2 || raw[0]["asset_id"] != "id-a" {
		t.Fatalf("bindings=%v", raw)
	}
}
