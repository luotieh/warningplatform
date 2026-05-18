package scanrunner

import (
	"testing"

	"vulnscan-backend/model"
)

func TestMergePresetWithParameters_orderAndStripMeta(t *testing.T) {
	params := model.JSONMap{
		"engine_preset":             "conservative",
		"rate_limit":                200,
		"worker_target_sharding":    true,
		"nuclei_interactsh_disable": false,
	}
	got := MergePresetWithParameters(params)
	if _, ok := got["engine_preset"]; ok {
		t.Fatal("engine_preset should be stripped from merged config")
	}
	// preset conservative has rate_limit 40, task overrides to 200
	if got["rate_limit"] != 200 {
		t.Fatalf("task parameters should override preset, got rate_limit=%v", got["rate_limit"])
	}
	if got["nuclei_interactsh_disable"] != false {
		t.Fatalf("task should override preset nuclei_interactsh_disable, got %v", got["nuclei_interactsh_disable"])
	}
	if got["worker_target_sharding"] != true {
		t.Fatal("non-preset keys should be preserved")
	}
}

func TestMergePresetWithParameters_unknownPreset(t *testing.T) {
	got := MergePresetWithParameters(model.JSONMap{
		"engine_preset": "no_such_preset",
		"rate_limit":    99,
	})
	if got["rate_limit"] != 99 {
		t.Fatalf("expected only task params, got %#v", got)
	}
}
