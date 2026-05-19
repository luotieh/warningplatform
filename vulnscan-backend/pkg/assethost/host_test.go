package assethost

import "testing"

func TestPrimaryHostPrefersSubdomain(t *testing.T) {
	got := PrimaryHost("hr.code.yt-security.com", "", "code.yt-security.com", "")
	if got != "hr.code.yt-security.com" {
		t.Fatalf("got %q", got)
	}
}

func TestShouldApplyPTRDomainBlocksApexDowngrade(t *testing.T) {
	if ShouldApplyPTRDomain("hr.code.yt-security.com", "", "", "发现子域名: hr.code.yt-security.com", "code.yt-security.com") {
		t.Fatal("expected false when PTR is parent of known subdomain")
	}
}

func TestHostFromSubdomainDiscoveryName(t *testing.T) {
	got := HostFromSubdomainDiscoveryName("发现子域名: hr.code.yt-security.com")
	if got != "hr.code.yt-security.com" {
		t.Fatalf("got %q", got)
	}
}
