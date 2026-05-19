package analyzer

import "testing"

func TestExtractSensitiveWordEvidence(t *testing.T) {
	src := "这是一段包含少妇词语的测试文本，用于验证上下文与高亮。"
	ctx, contexts, htmlOut := extractSensitiveWordEvidence(src, "少妇", "medium")
	if ctx == "" {
		t.Fatal("expected context")
	}
	if len(contexts) == 0 {
		t.Fatal("expected contexts")
	}
	if htmlOut == "" || !stringsContains(htmlOut, "<mark") {
		t.Fatalf("expected highlighted html, got %q", htmlOut)
	}
	if !stringsContains(htmlOut, "少妇") {
		t.Fatalf("expected highlighted word in full text, got %q", htmlOut)
	}
}

func TestBuildPageEvidenceHTMLMultiHit(t *testing.T) {
	src := "甲少妇乙黑链丙少妇丁"
	htmlOut := buildPageEvidenceHTML(src, []wordHit{
		{word: "少妇", severity: "medium"},
		{word: "黑链", severity: "high"},
	})
	if htmlOut == "" || !stringsContains(htmlOut, "<mark") {
		t.Fatalf("expected html, got %q", htmlOut)
	}
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexStr(s, sub) >= 0)
}

func indexStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
