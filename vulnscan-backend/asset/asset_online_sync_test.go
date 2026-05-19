package asset

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vulnscan-backend/model"
)

func TestBuildAssetOnlineProbePrefersMonitorHomepage(t *testing.T) {
	asset := model.Asset{ID: "a1", Address: "10.0.0.1"}
	task := &model.MonitorPathTask{
		AssetID:            "a1",
		URLOverride:        "https://monitor.example.com",
		Enabled:            true,
		ConfigAvailability: model.JSONMap{"enabled": true},
	}
	probe, ok := buildAssetOnlineProbe(asset, task)
	if !ok || probe.mode != "http" || probe.target != "https://monitor.example.com" {
		t.Fatalf("unexpected probe: %+v ok=%v", probe, ok)
	}
}

func TestFilterAssetsForProbeCooldown(t *testing.T) {
	now := time.Now()
	recent := now.Add(-2 * time.Minute)
	assets := []model.Asset{
		{ID: "a1", ReachableCheckedAt: &recent},
		{ID: "a2"},
	}
	out, skipped := filterAssetsForProbeCooldown(assets)
	if skipped != 1 || len(out) != 1 || out[0].ID != "a2" {
		t.Fatalf("got out=%v skipped=%d", out, skipped)
	}
}

func TestNormalizeAssetProbeHTTPURL(t *testing.T) {
	if got := normalizeAssetProbeHTTPURL("oa.example.com"); got != "http://oa.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestProbeAssetOnlineHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	probe := assetOnlineProbe{mode: "http", target: srv.URL}
	if !probeAssetOnline(context.Background(), probe) {
		t.Fatal("expected online")
	}
}
