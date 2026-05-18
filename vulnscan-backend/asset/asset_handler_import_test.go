package asset

import "testing"

func TestBuildHeaderMap_ledgerImportTemplate(t *testing.T) {
	headers := []string{
		"系统名称(必填)",
		"单位名称(必填)",
		"资产分类(必填)",
		"是否联网(必填)",
		"IPv4地址",
		"IPv6地址(必填)",
		"访问地址(必填)",
		"是否是关键信息基础设施(必填)",
		"安全防护等级(必填)",
	}
	m := buildHeaderMap(headers)

	assertFieldIndex := func(field string, want int) {
		t.Helper()
		if got, ok := m[field]; !ok || got != want {
			t.Fatalf("field %q index = %d (ok=%v), want %d; map=%v", field, got, ok, want, m)
		}
	}

	assertFieldIndex("name", 0)
	assertFieldIndex("organize_name", 1)
	assertFieldIndex("asset_family", 2)
	assertFieldIndex("is_online", 3)
	assertFieldIndex("ipv4", 4)
	assertFieldIndex("ipv6", 5)
	assertFieldIndex("address", 6)
	assertFieldIndex("is_key", 7)
	assertFieldIndex("security_protection_level", 8)
}

func TestCanonicalAssetFamily_ChineseLabels(t *testing.T) {
	cases := map[string]string{
		"域名网站": "domain_site",
		"业务系统": "business_system",
		"其他":   "other",
		"IP资产": "ip",
	}
	for in, want := range cases {
		if got := canonicalAssetFamily(in); got != want {
			t.Fatalf("canonicalAssetFamily(%q) = %q, want %q", in, got, want)
		}
	}
}
