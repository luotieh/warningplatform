package asset

import "testing"

func TestAssetLedgerColumnsVisibleExcludesConstruction(t *testing.T) {
	visible := assetLedgerColumnsVisible()
	for _, col := range visible {
		if isConstructionOrgColumn(col.Field) {
			t.Fatalf("visible columns should not include construction: %s", col.Field)
		}
	}
	foundOp := false
	for _, col := range visible {
		if col.Field == "operation_org" {
			foundOp = true
		}
	}
	if !foundOp {
		t.Fatal("operation_org should remain in visible columns")
	}
}
