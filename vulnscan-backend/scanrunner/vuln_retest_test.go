package scanrunner

import (
	"testing"

	"vulnscan-backend/model"
)

func TestSameRetestTarget_URLAndHost(t *testing.T) {
	v := &model.Vulnerability{Target: "example.com", Port: 443}
	f := &model.ScanFinding{Target: "https://example.com:443/path", Port: 0}
	if !sameRetestTarget(f, v) {
		t.Fatal("expected URL host to match vuln host")
	}
}

func TestMatchRetestFinding_byTemplateID(t *testing.T) {
	v := &model.Vulnerability{
		Title:      "Different Title",
		Target:     "example.com",
		TemplateID: "cve-2024-test",
	}
	f := model.ScanFinding{
		Target:   "https://example.com",
		Title:    "Nuclei Info Name",
		ModuleID: "nuclei-poc",
		Data:     model.JSONMap{"template_id": "cve-2024-test"},
	}
	m := matchRetestFinding([]model.ScanFinding{f}, v, nil)
	if m == nil {
		t.Fatal("expected template_id match")
	}
}

func TestBuildRetestTarget_fromEvidence(t *testing.T) {
	v := &model.Vulnerability{
		Target:   "example.com",
		Evidence: "Template: x\nMatched: https://example.com/vuln?q=1\n",
	}
	got := buildRetestTarget(v)
	if got != "https://example.com/vuln?q=1" {
		t.Fatalf("got %q", got)
	}
}
