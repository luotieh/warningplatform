package analyzer

import (
	"strings"
	"testing"
)

func TestBuildTamperCompareEvidence(t *testing.T) {
	ev := buildTamperCompareEvidence("hello old world", "hello new world")
	if ev.BaselineHTML == "" || ev.CurrentHTML == "" {
		t.Fatal("expected html evidence")
	}
	if !strings.Contains(ev.BaselineHTML, "tp-del") {
		t.Fatalf("expected deletion mark in baseline, got %q", ev.BaselineHTML)
	}
	if !strings.Contains(ev.CurrentHTML, "tp-ins") {
		t.Fatalf("expected insertion mark in current, got %q", ev.CurrentHTML)
	}
}
