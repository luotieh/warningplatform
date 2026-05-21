package scanrunner

import (
	"testing"

	"vulnscan-backend/model"
)

func TestDeriveScanParameters_smallTarget(t *testing.T) {
	got := DeriveScanParameters(2)
	if got["rate_limit"].(int) != 150 {
		t.Fatalf("rate_limit=%v want 150", got["rate_limit"])
	}
}

func TestApplyDerivedAndPreset_manualOverride(t *testing.T) {
	params := model.JSONMap{
		"engine_preset": "auto",
		"target_count":  100,
		"rate_limit":    10,
	}
	got := ApplyDerivedAndPreset(params)
	if got["rate_limit"].(int) != 10 {
		t.Fatalf("manual rate_limit should win, got %v", got["rate_limit"])
	}
}
