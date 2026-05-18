package company

import "testing"

func TestExtractDomainsFromStringSkipsHTML(t *testing.T) {
	input := `<html><body><a href="https://tool.chinaz.com">tool</a></body></html>`
	result := extractDomainsFromString(input)
	if len(result) != 0 {
		t.Fatalf("expected no domains from html, got %v", result)
	}
}

func TestExtractDomainsFromJSONStructuredPayload(t *testing.T) {
	payload := map[string]interface{}{
		"domains": []interface{}{"app.example.com", "www.example.com"},
		"meta": map[string]interface{}{
			"company": "Example",
		},
	}
	result := extractDomainsFromJSON(payload)
	if len(result) != 2 {
		t.Fatalf("expected 2 domains, got %v", result)
	}
}

func TestScoreDomainAssetRejectsUnrelatedICPDomain(t *testing.T) {
	rc := &reconContext{
		companyName:     "云天安全",
		explicitCompany: true,
		seedDomains:     []string{"yt-security.com"},
		seedRoots:       []string{"yt-security.com"},
	}
	score, reason, keep, _ := scoreDomainAsset("tool.chinaz.com", "icp_beian", map[string]string{
		"query_company": "云天安全",
	}, rc)
	if keep {
		t.Fatalf("expected unrelated domain to be dropped, got score=%d reason=%s", score, reason)
	}
}

func TestScoreDomainAssetExplainsConfidence(t *testing.T) {
	rc := &reconContext{
		companyName:     "YT Security",
		explicitCompany: true,
		seedDomains:     []string{"yt-security.com"},
		seedRoots:       []string{"yt-security.com"},
		companyTokens:   []string{"yt", "security"},
	}
	score, reason, keep, annotations := scoreDomainAsset("app.yt-security.com", "crt.sh", map[string]string{
		"org": "YT Security",
	}, rc)
	if !keep {
		t.Fatalf("expected related domain to be kept")
	}
	if score < 80 {
		t.Fatalf("expected score >= 80, got %d", score)
	}
	if reason == "" || annotations["matched_seed"] == "" {
		t.Fatalf("expected confidence explanation and matched seed, got reason=%q annotations=%v", reason, annotations)
	}
}
