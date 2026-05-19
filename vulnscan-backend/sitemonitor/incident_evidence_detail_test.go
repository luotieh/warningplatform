package sitemonitor

import (
	"strings"
	"testing"
)

func TestHtmlEvidenceToPlain(t *testing.T) {
	in := `<del class="tp-del">removed</del> same <ins class="tp-ins">added</ins>`
	out := htmlEvidenceToPlain(in)
	if !strings.Contains(out, "[-removed-]") || !strings.Contains(out, "[+added+]") {
		t.Fatalf("unexpected plain output: %q", out)
	}
}
