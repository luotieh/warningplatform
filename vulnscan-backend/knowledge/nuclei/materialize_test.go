package nuclei

import (
	"os"
	"testing"
)

func TestMaterializePocTemplates_dedupAndStable(t *testing.T) {
	root := t.TempDir()
	t.Setenv("VULNSCAN_NUCLEI_POCS_CACHE_DIR", root)

	a := &PocEntry{ID: "a", RawContent: "id: a-test\ninfo:\n  name: x\n  severity: info\nhttp: []\n"}
	b := &PocEntry{ID: "b", RawContent: "id: a-test\ninfo:\n  name: x\n  severity: info\nhttp: []\n"}

	paths1, err := materializePocTemplates([]*PocEntry{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths1) != 1 {
		t.Fatalf("same content should dedupe to one path, got %d: %v", len(paths1), paths1)
	}

	paths2, err := materializePocTemplates([]*PocEntry{a})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths2) != 1 || paths1[0] != paths2[0] {
		t.Fatalf("stable path: %v vs %v", paths1, paths2)
	}

	fi, err := os.Stat(paths1[0])
	if err != nil || fi.Size() == 0 {
		t.Fatalf("file missing or empty: %v", err)
	}
}

func TestPocTemplateCacheBase_envOverride(t *testing.T) {
	root := t.TempDir()
	t.Setenv("VULNSCAN_NUCLEI_POCS_CACHE_DIR", root)
	got := pocTemplateCacheBase()
	if got != root {
		t.Fatalf("expected %q got %q", root, got)
	}
}
