package nuclei

import "testing"

func TestMatchVersionRange(t *testing.T) {
	tests := []struct {
		version  string
		rangeStr string
		expect   bool
	}{
		{"2.4.49", "< 2.4.50", true},
		{"2.4.50", "< 2.4.50", false},
		{"2.4.49", ">= 2.4.0, < 2.4.50", true},
		{"2.3.9", ">= 2.4.0, < 2.4.50", false},
		{"2.4.50", ">= 2.4.0, < 2.4.50", false},
		{"8.0.27", ">= 8.0 AND < 8.0.28", true},
		{"8.0.28", ">= 8.0 AND < 8.0.28", false},
		{"1.0.0", "<= 1.0.0 || >= 2.0.0, < 2.1.0", true},
		{"2.0.5", "<= 1.0.0 || >= 2.0.0, < 2.1.0", true},
		{"1.5.0", "<= 1.0.0 || >= 2.0.0, < 2.1.0", false},
		{"1.2.3", "all", true},
		{"1.2.3", "*", true},
		{"1.2.3", "1.2.3", true},
		{"1.2.4", "1.2.3", false},
		{"v2.4.49", "< 2.4.50", true},
		{"", "< 2.4.50", false},
		{"2.4.49", "", false},
		{"3.0", "> 2.0", true},
		{"1.0", "> 2.0", false},
		{"2.0.0", "!= 2.0.0", false},
		{"2.0.1", "!= 2.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.version+"_in_"+tt.rangeStr, func(t *testing.T) {
			got := MatchVersionRange(tt.version, tt.rangeStr)
			if got != tt.expect {
				t.Errorf("MatchVersionRange(%q, %q) = %v, want %v", tt.version, tt.rangeStr, got, tt.expect)
			}
		})
	}
}

func TestParseDetectedProducts(t *testing.T) {
	tests := []struct {
		input  []string
		expect []DetectedProduct
	}{
		{
			[]string{"apache"},
			[]DetectedProduct{{Name: "apache"}},
		},
		{
			[]string{"apache:2.4.49"},
			[]DetectedProduct{{Name: "apache", Version: "2.4.49"}},
		},
		{
			[]string{"apache/httpd:2.4.49"},
			[]DetectedProduct{{Vendor: "apache", Name: "httpd", Version: "2.4.49"}},
		},
		{
			[]string{"nginx", "php:8.1"},
			[]DetectedProduct{{Name: "nginx"}, {Name: "php", Version: "8.1"}},
		},
		{
			[]string{""},
			[]DetectedProduct{},
		},
	}

	for i, tt := range tests {
		got := ParseDetectedProducts(tt.input)
		if len(got) != len(tt.expect) {
			t.Errorf("case %d: got %d products, want %d", i, len(got), len(tt.expect))
			continue
		}
		for j, dp := range got {
			if dp.Name != tt.expect[j].Name || dp.Version != tt.expect[j].Version || dp.Vendor != tt.expect[j].Vendor {
				t.Errorf("case %d[%d]: got %+v, want %+v", i, j, dp, tt.expect[j])
			}
		}
	}
}

func TestParseSemVersion(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
		major int
		minor int
		patch int
	}{
		{"2.4.49", true, 2, 4, 49},
		{"v1.0.0", true, 1, 0, 0},
		{"8.0", true, 8, 0, 0},
		{"3", true, 3, 0, 0},
		{"", false, 0, 0, 0},
		{"abc", false, 0, 0, 0},
	}

	for _, tt := range tests {
		sv, ok := parseSemVersion(tt.input)
		if ok != tt.ok {
			t.Errorf("parseSemVersion(%q) ok=%v, want %v", tt.input, ok, tt.ok)
			continue
		}
		if ok && (sv.Major != tt.major || sv.Minor != tt.minor || sv.Patch != tt.patch) {
			t.Errorf("parseSemVersion(%q) = %d.%d.%d, want %d.%d.%d",
				tt.input, sv.Major, sv.Minor, sv.Patch, tt.major, tt.minor, tt.patch)
		}
	}
}
