package nuclei

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectFilesystemTemplateSources_dir(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "tmpl")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{
		"nuclei_template_dir": sub,
	}
	tpl, wf, ok, err := CollectFilesystemTemplateSources(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(wf) != 0 || len(tpl) != 1 {
		t.Fatalf("ok=%v tpl=%v wf=%v", ok, tpl, wf)
	}
}

func TestTargetsFromScanLines(t *testing.T) {
	t.Parallel()
	ts := TargetsFromScanLines([]string{" 192.0.2.1 ", "https://example.com/x"})
	if len(ts) != 2 {
		t.Fatalf("len=%d", len(ts))
	}
	if ts[0].Host != "192.0.2.1" {
		t.Fatalf("host %v", ts[0])
	}
	if ts[1].URL != "https://example.com/x" {
		t.Fatalf("url %v", ts[1])
	}
}
