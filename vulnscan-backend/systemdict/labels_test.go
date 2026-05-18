package systemdict

import "testing"

func TestDefaultDictLabelsAssetFamily(t *testing.T) {
	labels := DefaultDictLabels("asset_family")
	if len(labels) < 5 {
		t.Fatalf("expected asset_family defaults, got %v", labels)
	}
}

func TestEnabledDictLabelsNilDBUsesDefaults(t *testing.T) {
	labels := EnabledDictLabels(nil, "asset_family")
	if len(labels) == 0 {
		t.Fatal("expected fallback defaults")
	}
}
