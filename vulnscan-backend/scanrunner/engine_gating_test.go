package scanrunner

import (
	"context"
	"testing"

	"vulnscan-backend/scan/core"
)

type stubScanModule struct {
	id string
}

func (s stubScanModule) ID() string       { return s.id }
func (s stubScanModule) Name() string     { return s.id }
func (s stubScanModule) Category() string { return "test" }
func (s stubScanModule) Run(context.Context, []*core.Target, map[string]interface{}) (*core.ModuleResult, error) {
	return nil, nil
}

func TestHasHTTPFromStageContext(t *testing.T) {
	t.Parallel()
	if hasHTTPFromStageContext(nil) {
		t.Fatal("nil ctx")
	}
	ctx := &StageContext{CompletedStages: map[string]StageResult{
		"s1": {Findings: []*core.Finding{{
			ModuleID: "service_probe",
			Type:     "service",
			Target:   &core.Target{Protocol: "HTTP/1.1"},
		}}},
	}}
	if !hasHTTPFromStageContext(ctx) {
		t.Fatal("expected http from protocol")
	}
	ctx2 := &StageContext{CompletedStages: map[string]StageResult{
		"s1": {Findings: []*core.Finding{{
			Type:   "port_open",
			Target: &core.Target{Port: 443},
		}}},
	}}
	if !hasHTTPFromStageContext(ctx2) {
		t.Fatal("expected http from port 443")
	}
	ctx3 := &StageContext{CompletedStages: map[string]StageResult{
		"s1": {Findings: []*core.Finding{{Type: "dns_record"}}},
	}}
	if hasHTTPFromStageContext(ctx3) {
		t.Fatal("no http signal")
	}
}

func TestFilterWebVulnModules(t *testing.T) {
	t.Parallel()
	mods := []core.ScanModule{stubScanModule{"sqli"}, stubScanModule{"dns_all"}}
	cfg := map[string]interface{}{configKeySkipWebModules: true}
	out := filterWebVulnModules(mods, cfg)
	if len(out) != 1 || out[0].ID() != "dns_all" {
		t.Fatalf("got %#v", out)
	}
	out2 := filterWebVulnModules(mods, map[string]interface{}{configKeySkipWebModules: false})
	if len(out2) != 2 {
		t.Fatal("flag false should keep all")
	}
}
