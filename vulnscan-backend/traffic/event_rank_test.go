package traffic

import (
	"context"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func seedRankEvents(t *testing.T, st store.Store) {
	t.Helper()
	events := []domain.Event{
		{EventID: "evt-dns-1", EventName: "DNS命中IOC", Severity: "high",
			Context: `{"event_type":"dns","src_ip":"10.0.0.1","dst_ip":"1.2.3.4","ioc":{"ioc_type":"ip","ioc_value":"1.2.3.4"}}`},
		{EventID: "evt-dns-2", EventName: "普通DNS", Severity: "low",
			Context: `{"event_type":"dns","src_ip":"10.0.0.2","dst_ip":"1.2.3.4"}`},
		{EventID: "evt-scan-1", EventName: "端口扫描", Severity: "medium",
			Context: `{"event_type":"scan","src_ip":"10.0.0.1","dst_ip":"10.0.0.9"}`},
	}
	for _, e := range events {
		if _, err := st.CreateEvent(e); err != nil {
			t.Fatal(err)
		}
	}
}

// 排行统计按列表展示口径：attackDevice 含 IOC 归属修正，typeText 为类型展示名。
func TestRankCountsMatchDisplaySemantics(t *testing.T) {
	svc, st := newTestEventService(t, "")
	seedRankEvents(t, st)
	ranks, err := svc.RankCounts(context.Background(), store.EventQuery{Scope: "all"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]int{}
	for key, items := range ranks {
		got[key] = map[string]int{}
		for _, item := range items {
			got[key][item.Name] = item.Value
		}
	}
	// IOC 归属修正：evt-dns-1 的威胁侧是 IOC（1.2.3.4）而非报文源 IP（10.0.0.1）。
	if got["attackDevice"]["1.2.3.4"] != 1 || got["attackDevice"]["10.0.0.2"] != 1 || got["attackDevice"]["10.0.0.1"] != 1 {
		t.Fatalf("attackDevice=%v", got["attackDevice"])
	}
	if got["victimDevice"]["10.0.0.1"] != 1 || got["victimDevice"]["1.2.3.4"] != 1 || got["victimDevice"]["10.0.0.9"] != 1 {
		t.Fatalf("victimDevice=%v", got["victimDevice"])
	}
	// 类型展示名：dns→DNS（2 条）、scan→扫描（1 条）。
	if got["typeText"]["DNS"] != 2 || got["typeText"]["扫描"] != 1 {
		t.Fatalf("typeText=%v", got["typeText"])
	}
}

// 排行筛选的分页在筛选之后生效：总数是筛选后的数量，每页数量一致。
func TestListPageRankFilterPaginatesAfterFiltering(t *testing.T) {
	svc, st := newTestEventService(t, "")
	seedRankEvents(t, st)

	// IOC 归属修正口径：attackDevice=1.2.3.4 只命中 evt-dns-1。
	rows, total, err := svc.ListPage(context.Background(), store.EventQuery{
		Scope: "all", Page: 1, PageSize: 10, RankKey: "attackDevice", RankValue: "1.2.3.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 || rows[0]["event_id"] != "evt-dns-1" {
		t.Fatalf("attackDevice filter total=%d rows=%v", total, rows)
	}

	// typeText=DNS 命中 2 条：page_size=1 时第 2 页仍有 1 条（修复前总数是未筛选值）。
	rows, total, err = svc.ListPage(context.Background(), store.EventQuery{
		Scope: "all", Page: 2, PageSize: 1, RankKey: "typeText", RankValue: "DNS",
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 1 {
		t.Fatalf("typeText page2 total=%d rows=%d want 2/1", total, len(rows))
	}
	if rows[0]["event_id"] == "evt-scan-1" {
		t.Fatalf("scan event should not match typeText=DNS: %v", rows[0]["event_id"])
	}

	// 无排行筛选时原逻辑不变。
	_, total, err = svc.ListPage(context.Background(), store.EventQuery{Scope: "all", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("unfiltered total=%d want 3", total)
	}
}

// 非法排行维度报错，不静默退化为全量列表。
func TestListPageRankFilterRejectsUnknownKey(t *testing.T) {
	svc, st := newTestEventService(t, "")
	seedRankEvents(t, st)
	_, _, err := svc.ListPage(context.Background(), store.EventQuery{
		Scope: "all", Page: 1, PageSize: 10, RankKey: "severity", RankValue: "high",
	})
	if err == nil {
		t.Fatal("invalid rank key should fail")
	}
}
