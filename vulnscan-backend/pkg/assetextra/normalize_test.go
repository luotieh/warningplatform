package assetextra

import (
	"testing"

	"vulnscan-backend/model"
)

func TestNormalizeMapStripsUnitProfile(t *testing.T) {
	out := NormalizeMap(model.JSONMap{
		"unit_type":          "事业单位",
		"leader_name":        "张三",
		"custom_field":       "keep",
		KeyRegionCode:        "320302",
		KeyUnitDetailAddress: "legacy",
	})
	if _, ok := out["unit_type"]; ok {
		t.Fatal("unit_type should be stripped")
	}
	if out["custom_field"] != "keep" {
		t.Fatalf("custom_field=%v", out["custom_field"])
	}
}
