package service

import (
	"testing"

	"vulnscan-backend/traffic/internal/store"
	"vulnscan-backend/traffic/internal/domain"
)

func TestBuildOccurrence(t *testing.T) {
	occ := buildOccurrence(map[string]any{
		"occurrence_time": "2026-06-30T09:00:00Z",
		"wire_bytes":      float64(1480),
		"packets":         float64(3),
	})
	if occ["time"] != "2026-06-30T09:00:00Z" {
		t.Fatalf("time=%v", occ["time"])
	}
	if occ["wire_bytes"] != 1480 {
		t.Fatalf("wire_bytes=%v (want int 1480)", occ["wire_bytes"])
	}
	if occ["packets"] != 3 {
		t.Fatalf("packets=%v (want int 3)", occ["packets"])
	}
}

func TestBuildOccurrenceOmitsMissing(t *testing.T) {
	occ := buildOccurrence(map[string]any{"time": "2026-06-30T10:00:00Z"})
	if occ["time"] != "2026-06-30T10:00:00Z" {
		t.Fatalf("time=%v", occ["time"])
	}
	if _, ok := occ["wire_bytes"]; ok {
		t.Fatal("wire_bytes should be omitted when missing")
	}
	if _, ok := occ["packets"]; ok {
		t.Fatal("packets should be omitted when missing")
	}
}

func TestMergeOccurrenceStoresObjects(t *testing.T) {
	st := store.NewMemoryStore()
	created, _ := st.CreateEvent(domain.Event{EventID: "evt-occ", Context: `{"occurrence_count":1,"occurrences":[{"time":"2026-06-30T09:00:00Z","wire_bytes":100,"packets":1}]}`})
	svc := Services{Store: st}
	count := svc.mergeOccurrence(created.EventID, map[string]any{
		"occurrence_time": "2026-06-30T09:05:00Z",
		"wire_bytes":      float64(250),
		"packets":         float64(2),
	})
	if count != 2 {
		t.Fatalf("count=%d want 2", count)
	}
	got, _ := st.GetEvent("evt-occ")
	// occurrences 应为对象列表，新追加项含 wire_bytes/packets
	if got.Context == "" || !containsJSON(got.Context, `"wire_bytes":250`) || !containsJSON(got.Context, `"packets":2`) {
		t.Fatalf("merged occurrence object missing: %s", got.Context)
	}
}

func containsJSON(haystack, needle string) bool {
	return len(haystack) > 0 && len(needle) > 0 && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
