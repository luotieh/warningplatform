package service

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestModelTimeContextBeijing(t *testing.T) {
	raw := `{"first_time":"2026-10-12T06:53:00Z","last_time":"2026-10-12T06:56:00Z","window":{"start":"2026-10-12T16:53:00Z","end":"2026-10-12T16:56:00Z"},"payload_text":"2026-10-12T06:53:00Z","timestamp":1791787980000000001,"entries":[{"created_at":"2026-10-12T14:53:00+08:00"}]}`
	projected := ModelTimeContext(raw)
	for _, expected := range []string{"2026-10-12T14:53:00+08:00", "2026-10-12T14:56:00+08:00", "2026-10-13T00:53:00+08:00", "2026-10-13T00:56:00+08:00", "1791787980000000001"} {
		if !strings.Contains(projected, expected) {
			t.Fatalf("missing %s in %s", expected, projected)
		}
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(projected), &value); err != nil {
		t.Fatal(err)
	}
	if value["payload_text"] != "2026-10-12T06:53:00Z" {
		t.Fatal("raw payload changed")
	}
	if ModelTimeContext(projected) != projected {
		t.Fatal("conversion is not idempotent")
	}
	if ModelTimeContext("unstructured input") != "unstructured input" {
		t.Fatal("non-JSON changed")
	}
}
