package asset

import "testing"

func TestNormalizeAssetFamilyValue(t *testing.T) {
	tests := []struct {
		name        string
		assetFamily string
		systemType  string
		assetType   string
		domain      string
		want        string
	}{
		{name: "prefer asset family", assetFamily: "software", systemType: "hardware", want: "software"},
		{name: "keep other asset family", assetFamily: "other", want: "other"},
		{name: "fallback to system type", systemType: "official-account", want: "official_account"},
		{name: "fallback to type", assetType: "business_system", want: "business_system"},
		{name: "infer domain asset", domain: "example.com", want: "domain_site"},
		{name: "default to ip", want: "ip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeAssetFamilyValue(tt.assetFamily, tt.systemType, tt.assetType, tt.domain, "", "")
			if got != tt.want {
				t.Fatalf("normalizeAssetFamilyValue() = %q, want %q", got, tt.want)
			}
		})
	}
}
