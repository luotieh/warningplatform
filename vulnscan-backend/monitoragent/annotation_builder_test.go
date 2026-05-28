package monitoragent

import (
	"strings"
	"testing"
)

func TestBuildTamperAnnotationsFallsBackToPageHighlight(t *testing.T) {
	annotations := buildTamperAnnotations(map[string]any{
		"diffs": []any{
			map[string]any{
				"type":     "content_hash",
				"baseline": "old",
				"current":  "new",
			},
			map[string]any{
				"type":     "text_length",
				"baseline": float64(1789),
				"current":  float64(2363),
			},
		},
	})

	if len(annotations) != 1 {
		t.Fatalf("expected one fallback annotation, got %d", len(annotations))
	}
	if annotations[0].Type != "page" {
		t.Fatalf("expected page annotation, got %q", annotations[0].Type)
	}
	if annotations[0].Label == "" {
		t.Fatal("expected fallback annotation label")
	}
}

func TestBuildAnnotationJSSupportsPageHighlight(t *testing.T) {
	js := buildAnnotationJS([]IssueAnnotation{{
		Type:  "page",
		Label: "检测到页面内容变化",
	}})

	if !strings.Contains(js, "highlightPage('检测到页面内容变化');") {
		t.Fatalf("expected page highlight call in js: %s", js)
	}
	if !strings.Contains(js, "position:fixed") || !strings.Contains(js, "#ef4444") {
		t.Fatalf("expected fixed red page border style in js: %s", js)
	}
}
