package nuclei

import (
	"os"
	"testing"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
)

func TestMergeInteractshNucleiOptions_disable(t *testing.T) {
	t.Parallel()
	opts := mergeInteractshNucleiOptions(nil, map[string]interface{}{
		"nuclei_interactsh_disable": true,
	})
	if len(opts) != 1 {
		t.Fatalf("len=%d", len(opts))
	}
	e, err := nucleilib.NewNucleiEngineCtx(t.Context(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
}

func TestMergeInteractshNucleiOptions_envAddsOpt(t *testing.T) {
	t.Setenv("VULNSCAN_NUCLEI_INTERACTSH_URL", "https://oob.example.com")
	t.Setenv("VULNSCAN_NUCLEI_INTERACTSH_TOKEN", "secret")
	t.Cleanup(func() {
		os.Unsetenv("VULNSCAN_NUCLEI_INTERACTSH_URL")
		os.Unsetenv("VULNSCAN_NUCLEI_INTERACTSH_TOKEN")
	})
	opts := mergeInteractshNucleiOptions(nil, map[string]interface{}{})
	if len(opts) != 1 {
		t.Fatalf("expected 1 opt, got %d", len(opts))
	}
}
