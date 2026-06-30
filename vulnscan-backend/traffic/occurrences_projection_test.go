package traffic

import (
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func TestLyCompatibleEventExposesOccurrences(t *testing.T) {
	row := lyCompatibleEvent(domain.Event{
		EventID: "evt-1",
		Context: `{"occurrences":[{"time":"2026-06-30T09:00:00Z","wire_bytes":1480,"packets":3}]}`,
	})
	occ, ok := row["occurrences"].([]any)
	if !ok {
		t.Fatalf("occurrences not a list: %T", row["occurrences"])
	}
	if len(occ) != 1 {
		t.Fatalf("occurrences len=%d want 1", len(occ))
	}
}

func TestLyCompatibleEventOccurrencesEmpty(t *testing.T) {
	row := lyCompatibleEvent(domain.Event{EventID: "evt-2", Context: ""})
	// 无 context 时 occurrences 应为 nil（前端按空处理）
	if v, ok := row["occurrences"]; ok && v != nil {
		if list, isList := v.([]any); isList && len(list) != 0 {
			t.Fatalf("expected empty/nil occurrences, got %v", v)
		}
	}
}
