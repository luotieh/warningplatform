package scanrunner

import "testing"

func TestExpandScanTargetsCIDR24(t *testing.T) {
	out, err := ExpandScanTargets([]string{"10.20.30.0/24"}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 254 {
		t.Fatalf("want 254 hosts, got %d", len(out))
	}
}
