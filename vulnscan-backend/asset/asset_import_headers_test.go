package asset

import "testing"

func TestAssetImportColumns_TitleAliasesMatchFields(t *testing.T) {
	aliases := buildAssetImportTitleAliases()
	for _, col := range assetImportColumns {
		for _, header := range []string{col.Title, col.Title + "(必填)"} {
			key := normalizeHeader(header)
			got, ok := aliases[key]
			if !ok {
				t.Fatalf("missing alias for import column header %q (field %s)", header, col.Field)
			}
			if got != col.Field {
				t.Fatalf("header %q maps to %q, want %s", header, got, col.Field)
			}
		}
	}
}

func TestAssetLedgerColumns_TitleAliasesMatchFields(t *testing.T) {
	aliases := buildAssetImportTitleAliases()
	titleCounts := ledgerTitleUseCount()
	for _, col := range assetLedgerColumns {
		if got, ok := aliases[normalizeHeader(col.Field)]; !ok || got != col.Field {
			t.Fatalf("field alias %s missing or wrong: %q", col.Field, got)
		}
		if titleCounts[normalizeHeader(col.Title)] != 1 {
			continue
		}
		got, ok := aliases[normalizeHeader(col.Title)]
		if !ok || got != col.Field {
			t.Fatalf("ledger title %q maps to %q (ok=%v), want %s", col.Title, got, ok, col.Field)
		}
	}
}

func TestAssetImportLegacyTitleAliases_StillResolve(t *testing.T) {
	aliases := buildAssetImportTitleAliases()
	cases := map[string]string{
		"资产名称": "name",
		"地址":   "address",
	}
	for title, want := range cases {
		got, ok := aliases[normalizeHeader(title)]
		if !ok || got != want {
			t.Fatalf("legacy title %q => %q (ok=%v), want %s", title, got, ok, want)
		}
	}
}

func TestBuildGroupedHeaderMap_OperationOrgSection(t *testing.T) {
	groupRow := []string{
		"系统基本信息", "系统基本信息", "系统运维单位基本情况", "系统运维单位基本情况",
	}
	fieldRow := []string{"系统名称", "单位名称", "单位名称", "详细地址"}
	m := buildGroupedHeaderMap(groupRow, fieldRow)
	if m["name"] != 0 {
		t.Fatalf("name index = %d, want 0", m["name"])
	}
	if m["organize_name"] != 1 {
		t.Fatalf("organize_name index = %d, want 1", m["organize_name"])
	}
	if m["operation_org"] != 2 {
		t.Fatalf("operation_org index = %d, want 2", m["operation_org"])
	}
	if m["operation_org_address"] != 3 {
		t.Fatalf("operation_org_address index = %d, want 3", m["operation_org_address"])
	}
}
