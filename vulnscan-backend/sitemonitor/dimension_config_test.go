package sitemonitor

import (
	"testing"

	"vulnscan-backend/model"
)

func TestPathTaskHasScheduledDimensions(t *testing.T) {
	pt := &model.MonitorPathTask{
		ConfigAvailability: model.JSONMap{"enabled": true, "cycle_minutes": 5},
	}
	if !pathTaskHasScheduledDimensions(pt) {
		t.Fatal("expected schedulable path task")
	}
	pt2 := &model.MonitorPathTask{
		ConfigTamper: model.JSONMap{"enabled": false},
	}
	if pathTaskHasScheduledDimensions(pt2) {
		t.Fatal("expected no schedule when all disabled")
	}
}

func TestConfigEnabled(t *testing.T) {
	if !configEnabled(model.JSONMap{"enabled": true}) {
		t.Fatal("expected enabled true")
	}
	if configEnabled(model.JSONMap{"enabled": false}) {
		t.Fatal("expected enabled false")
	}
	if !configEnabled(model.JSONMap{"cron": "0 * * * *"}) {
		t.Fatal("missing enabled should default true")
	}
}
