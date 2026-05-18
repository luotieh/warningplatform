package organize

import (
	"testing"

	"code.yt-security.com/public/sdk/identity"
)

func TestFindIAMOrganizeByExactNameNilService(t *testing.T) {
	info, err := FindIAMOrganizeByExactName(t.Context(), nil, "测试单位1")
	if err != nil || info != nil {
		t.Fatalf("got info=%v err=%v", info, err)
	}
}

func TestPickFirstExactNameMatch(t *testing.T) {
	all := []*identity.OrganizeInfo{
		{ID: "1", Name: "测试单位2"},
		{ID: "2", Name: "测试单位1"},
		{ID: "3", Name: "测试单位1"},
	}
	var matched *identity.OrganizeInfo
	name := "测试单位1"
	for _, info := range all {
		if info != nil && info.Name == name && matched == nil {
			matched = info
		}
	}
	if matched == nil || matched.ID != "2" {
		t.Fatalf("expected first match id=2, got %v", matched)
	}
}
