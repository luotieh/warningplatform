package scanrunner

import (
	"strings"
	"testing"

	"code.yt-security.com/public/scanengine/core"
)

func TestParseEnginePolicy_nestedAndTopLevel(t *testing.T) {
	t.Parallel()
	p := ParseEnginePolicy(map[string]interface{}{
		"engine": map[string]interface{}{
			"max_findings":                     100,
			"min_confidence":                   40,
			"strict_dedup":                     true,
			"auto_skip_web_vulns_without_http": true,
		},
		"engine.min_confidence": 80,
	})
	if p.MaxFindingsPersisted != 100 {
		t.Fatalf("max_findings: %d", p.MaxFindingsPersisted)
	}
	if p.MinConfidence != 80 {
		t.Fatalf("top-level should override nested min_confidence: %d", p.MinConfidence)
	}
	if !p.StrictDedup || !p.AutoSkipWebVulnsWithoutHTTP {
		t.Fatalf("strict or auto_skip not set")
	}
}

func TestAllowPersistFinding_minConfidenceVulnOnly(t *testing.T) {
	t.Parallel()
	p := EnginePolicy{MinConfidence: 80, MinConfidenceVulnOnly: true}
	f := &core.Finding{ModuleID: "dns_all", Type: "dns_record", Confidence: 10}
	if !p.AllowPersistFinding(f) {
		t.Fatal("recon should pass low confidence when vuln-only")
	}
	f2 := &core.Finding{ModuleID: "sqli", Type: "sql_injection", Confidence: 10}
	if p.AllowPersistFinding(f2) {
		t.Fatal("vuln should fail low confidence")
	}
}

func TestAllowPersistFinding_requireEvidence(t *testing.T) {
	t.Parallel()
	p := EnginePolicy{RequireVulnEvidence: true}
	f := &core.Finding{ModuleID: "sqli", Type: "sql_injection", Confidence: 99}
	if p.AllowPersistFinding(f) {
		t.Fatal("vuln without evidence/description/data should fail")
	}
	f2 := &core.Finding{ModuleID: "sqli", Type: "sql_injection", Confidence: 99, Description: strings.Repeat("x", 30), Evidence: "resp"}
	if !p.AllowPersistFinding(f2) {
		t.Fatal("with evidence should pass")
	}
}
