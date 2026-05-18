package organize

import (
	"testing"

	"vulnscan-backend/model"
)

func TestBuildOrganizeTreeFromFlat(t *testing.T) {
	roots := buildOrganizeTreeFromFlat([]model.Organize{
		{ID: "a", Name: "总部"},
		{ID: "b", Name: "分部", ParentID: "a"},
		{ID: "c", Name: "科室", ParentID: "b"},
	})
	if len(roots) != 1 || roots[0].ID != "a" {
		t.Fatalf("expected single root a, got %+v", roots)
	}
	if len(roots[0].Children) != 1 || roots[0].Children[0].ID != "b" {
		t.Fatalf("expected child b, got %+v", roots[0].Children)
	}
	if len(roots[0].Children[0].Children) != 1 || roots[0].Children[0].Children[0].ID != "c" {
		t.Fatalf("expected grandchild c")
	}
}
