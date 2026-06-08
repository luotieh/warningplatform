package organize

import (
	"testing"

	"code.yt-security.com/public/access/admin"
)

func TestBuildIAMOrganizeTreeFromInfos(t *testing.T) {
	roots := buildIAMOrganizeTree([]*admin.OrganizeInfo{
		{ID: "a", Name: "A"},
		{ID: "b", Name: "B", ParentID: "a"},
	})
	if len(roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(roots))
	}
	if roots[0].ID != "a" || len(roots[0].Children) != 1 || roots[0].Children[0].ID != "b" {
		t.Fatalf("unexpected tree: %+v", roots)
	}
}
