package analyzer

import (
	"testing"

	"vulnscan-backend/model"
)

func TestNeedsBaselineInit(t *testing.T) {
	if !needsBaselineInit(nil) {
		t.Fatal("nil should need init")
	}
	if !needsBaselineInit(&model.MonitorBaseline{ContentHash: "abc", BodyText: ""}) {
		t.Fatal("hash-only legacy baseline should re-init, not compare")
	}
	if needsBaselineInit(&model.MonitorBaseline{ContentHash: "abc", BodyText: "hello"}) {
		t.Fatal("baseline with body should be comparable")
	}
}
