package service

import (
	"encoding/json"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestNormalizeEvidenceFiles(t *testing.T) {
	files := normalizeEvidenceFiles(map[string]any{
		"device_id": "node-x",
		"evidence_files": []any{
			map[string]any{"name": "a.pcap", "path_ref": "/api/v1/evidence/node-x/a.pcap"},
		},
	}, 3, "2026-08-06T10:00:00Z")
	if len(files) != 1 {
		t.Fatalf("len=%d want 1", len(files))
	}
	ef := files[0].(map[string]any)
	if ef["device_id"] != "node-x" || ef["occ_idx"] != 3 || ef["occ_time"] != "2026-08-06T10:00:00Z" {
		t.Fatalf("metadata missing: %#v", ef)
	}
	if ef["name"] != "a.pcap" {
		t.Fatalf("original field lost: %#v", ef)
	}
}

func TestMergeEvidenceFilesDedup(t *testing.T) {
	ctx := map[string]any{}
	first := normalizeEvidenceFiles(map[string]any{
		"device_id": "node-x",
		"evidence_files": []any{
			map[string]any{"name": "a.pcap", "path_ref": "/api/v1/evidence/node-x/a.pcap"},
		},
	}, 0, "2026-08-06T10:00:00Z")
	mergeEvidenceFiles(ctx, first)

	second := normalizeEvidenceFiles(map[string]any{
		"device_id": "node-x",
		"evidence_files": []any{
			map[string]any{"name": "a.pcap", "path_ref": "/api/v1/evidence/node-x/a.pcap"},
			map[string]any{"name": "b.pcap", "path_ref": "/api/v1/evidence/node-x/b.pcap", "sha256": "abc"},
		},
	}, 1, "2026-08-06T10:01:00Z")
	mergeEvidenceFiles(ctx, second)

	files := ctx["evidence_files"].([]any)
	if len(files) != 2 {
		t.Fatalf("len=%d want 2 (dedup by path/sha256)", len(files))
	}
	if files[0].(map[string]any)["occ_idx"] != 0 {
		t.Fatalf("first entry occ_idx changed: %#v", files[0])
	}
	if files[1].(map[string]any)["occ_idx"] != 1 {
		t.Fatalf("second entry occ_idx wrong: %#v", files[1])
	}
}

func TestMergeEvidenceFilesSha256DedupWins(t *testing.T) {
	ctx := map[string]any{}
	mergeEvidenceFiles(ctx, []any{
		map[string]any{"name": "a.pcap", "path_ref": "/api/v1/evidence/x/a.pcap", "sha256": "same"},
	})
	mergeEvidenceFiles(ctx, []any{
		map[string]any{"name": "a-dup.pcap", "path_ref": "/api/v1/evidence/y/a.pcap", "sha256": "same"},
	})
	files := ctx["evidence_files"].([]any)
	if len(files) != 1 {
		t.Fatalf("sha256 dedup failed: len=%d", len(files))
	}
}

func TestMergeEvidenceFilesTruncates(t *testing.T) {
	ctx := map[string]any{}
	for i := 0; i < maxEvidenceFiles+5; i++ {
		mergeEvidenceFiles(ctx, []any{
			map[string]any{
				"name":     "f.pcap",
				"path_ref": "/api/v1/evidence/node-x/" + string(rune('a'+i)) + ".pcap",
			},
		})
	}
	files := ctx["evidence_files"].([]any)
	if len(files) != maxEvidenceFiles {
		t.Fatalf("len=%d want %d", len(files), maxEvidenceFiles)
	}
	if ctx["evidence_truncated"] != true {
		t.Fatal("evidence_truncated not set")
	}
}

func TestMergeOccurrenceAccumulatesEvidence(t *testing.T) {
	st := store.NewMemoryStore()
	created, _ := st.CreateEvent(domain.Event{
		EventID: "evt-evidence-merge",
		Context: mustJSONMap(map[string]any{
			"occurrence_count": 1,
			"occurrences": []any{
				map[string]any{"time": "2026-08-06T10:00:00Z"},
			},
			"evidence_files": []any{
				map[string]any{
					"name": "a.pcap", "path_ref": "/api/v1/evidence/node-x/a.pcap",
					"device_id": "node-x", "occ_idx": 0, "occ_time": "2026-08-06T10:00:00Z",
				},
			},
		}),
	})
	svc := Services{Store: st}
	svc.mergeOccurrence(created.EventID, map[string]any{
		"device_id":       "node-x",
		"occurrence_time": "2026-08-06T10:05:00Z",
		"evidence_files": []any{
			map[string]any{"name": "b.pcap", "path_ref": "/api/v1/evidence/node-x/b.pcap"},
		},
	})
	got, _ := st.GetEvent("evt-evidence-merge")
	var ctx map[string]any
	if err := json.Unmarshal([]byte(got.Context), &ctx); err != nil {
		t.Fatal(err)
	}
	files := ctx["evidence_files"].([]any)
	if len(files) != 2 {
		t.Fatalf("evidence len=%d want 2: %s", len(files), got.Context)
	}
	second := files[1].(map[string]any)
	if toInt(second["occ_idx"]) != 1 || second["occ_time"] != "2026-08-06T10:05:00Z" {
		t.Fatalf("second evidence metadata wrong: %#v", second)
	}
}

func mustJSONMap(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
