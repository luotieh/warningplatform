package traffic

import (
	"context"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestDisplayFiltersPaginationAndRanks(t *testing.T) {
	svc, st := newTestEventService(t, "")
	seedRankEvents(t, st)
	for _, asset := range []domain.Asset{
		{Name: "enabled", Address: "10.0.0.0/24", AssetType: "ip_segment", Status: 1},
		{Name: "disabled", Address: "1.2.3.4", AssetType: "ip", Status: 0},
	} {
		if _, err := st.CreateAsset(asset); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name  string
		query store.EventQuery
		total int
	}{
		{"tokens across fields", store.EventQuery{Keyword: "DNS 10.0.0.1"}, 1},
		{"translated type", store.EventQuery{Keyword: "扫描"}, 1},
		{"event ID", store.EventQuery{Keyword: "evt-dns-1"}, 1},
		{"IP exact", store.EventQuery{Asset: "10.0.0.1"}, 2},
		{"IP is not substring", store.EventQuery{Asset: "10.0.0"}, 0},
		{"CIDR", store.EventQuery{Asset: "10.0.0.0/24"}, 3},
		{"dotted mask", store.EventQuery{Asset: "10.0.0.0/255.255.255.0"}, 3},
		{"outside subnet", store.EventQuery{Asset: "192.168.0.0/24"}, 0},
		{"enabled assets", store.EventQuery{OnlyAssetRelated: true}, 3},
		{"combined filters", store.EventQuery{Asset: "10.0.0.0/24", Keyword: "DNS", RankKey: "typeText", RankValue: "DNS"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := tt.query
			q.Scope, q.PageSize = "all", 1
			for page := 1; page <= tt.total+1; page++ {
				q.Page = page
				rows, total, err := svc.ListPage(context.Background(), q)
				if err != nil || total != tt.total {
					t.Fatalf("total=%d want=%d err=%v", total, tt.total, err)
				}
				wantRows := 0
				if page <= tt.total {
					wantRows = 1
				}
				if len(rows) != wantRows {
					t.Fatalf("page=%d rows=%d want=%d", page, len(rows), wantRows)
				}
			}
			ranks, err := svc.RankCounts(context.Background(), q)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, item := range ranks["typeText"] {
				count += item.Value
			}
			if count != tt.total {
				t.Fatalf("ranks=%d total=%d", count, tt.total)
			}
		})
	}
}

func TestRegisteredAssetDisabledDoesNotMatch(t *testing.T) {
	svc, st := newTestEventService(t, "")
	seedRankEvents(t, st)
	if _, err := st.CreateAsset(domain.Asset{Name: "disabled", Address: "10.0.0.0/24", AssetType: "ip_segment", Status: 0}); err != nil {
		t.Fatal(err)
	}
	_, total, err := svc.ListPage(context.Background(), store.EventQuery{Scope: "all", OnlyAssetRelated: true})
	if err != nil || total != 0 {
		t.Fatalf("total=%d err=%v", total, err)
	}
}

func TestDisplayKeywordIOCAndEvidence(t *testing.T) {
	row := map[string]any{
		"attackDevice": "EXAMPLE.COM", "event_id": "evt-123", "type": "ti",
		"ioc":            map[string]any{"ioc_value": "example.com", "ioc_type": "domain"},
		"evidence_files": []any{map[string]any{"name": "capture.pcap"}},
	}
	for _, keyword := range []string{"EXAMPLE domain", "evt-123 情报", "example capture.pcap", "  example\tDOMAIN  "} {
		if !matchesDisplayKeyword(row, "情报", keyword) {
			t.Fatalf("should match %q", keyword)
		}
	}
	if matchesDisplayKeyword(row, "情报", "example missing") {
		t.Fatal("every token must match")
	}
}
