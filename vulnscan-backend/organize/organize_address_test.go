package organize

import (
	"testing"

	"vulnscan-backend/model"
)

func TestNormalizeOrganizeAddress(t *testing.T) {
	item := &model.Organize{Address: "", UnitDetailAddress: "海淀区1号"}
	NormalizeOrganizeAddress(item)
	if item.Address != "海淀区1号" || item.UnitDetailAddress != "" {
		t.Fatalf("merge detail: address=%q detail=%q", item.Address, item.UnitDetailAddress)
	}

	item2 := &model.Organize{Address: "北京市", UnitDetailAddress: "海淀区1号"}
	NormalizeOrganizeAddress(item2)
	if item2.Address != "北京市 海淀区1号" {
		t.Fatalf("concat: %q", item2.Address)
	}
}
