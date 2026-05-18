package model

import "testing"

func TestInferFindingCategory(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		moduleID    string
		findingType string
		want        string
	}{
		{
			name:        "recon module should stay recon even with custom type",
			moduleID:    "tech_detect",
			findingType: "framework_version",
			want:        FindingCategoryRecon,
		},
		{
			name:        "discover module should be folded into recon category",
			moduleID:    "port_scan",
			findingType: "service_banner",
			want:        FindingCategoryRecon,
		},
		{
			name:        "cert_check baseline cert_info is recon for inventory/enrich",
			moduleID:    "cert_check",
			findingType: "cert_info",
			want:        FindingCategoryRecon,
		},
		{
			name:        "unknown module falls back to finding type",
			moduleID:    "unknown_module",
			findingType: "web_info",
			want:        FindingCategoryRecon,
		},
		{
			name:        "unknown vuln-like finding defaults to vuln",
			moduleID:    "unknown_module",
			findingType: "sql_injection",
			want:        FindingCategoryVuln,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := InferFindingCategory(tc.moduleID, tc.findingType)
			if got != tc.want {
				t.Fatalf("InferFindingCategory(%q, %q) = %q, want %q", tc.moduleID, tc.findingType, got, tc.want)
			}
		})
	}
}
