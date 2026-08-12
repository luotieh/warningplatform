package store

import (
	"strings"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

func TestArchiveConvergedEventsAndPageScopes(t *testing.T) {
	st := NewMemoryStore()
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	recent := now.Add(-time.Hour)

	archivable := domain.Event{
		EventID: "evt-archivable", EventName: "旧事件", Severity: "high",
		AggregationClosed: true, LastSeenAt: &old,
	}
	closedRecent := domain.Event{
		EventID: "evt-closed-recent", EventName: "近收敛", Severity: "low",
		AggregationClosed: true, LastSeenAt: &recent,
	}
	openOld := domain.Event{
		EventID: "evt-open-old", EventName: "未收敛旧事件", Severity: "medium",
		AggregationClosed: false, LastSeenAt: &old,
	}
	for _, e := range []domain.Event{archivable, closedRecent, openOld} {
		if _, err := st.CreateEvent(e); err != nil {
			t.Fatal(err)
		}
	}

	// 只归档：已收敛 + 最后活跃早于今日 00:00（用 24h 前模拟）
	n, err := st.ArchiveConvergedEvents(now.Add(-24*time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("archived=%d want 1", n)
	}
	got, _ := st.GetEvent("evt-archivable")
	if got.ArchiveDate == nil || got.ArchiveDate.Format("2006-01-02") != old.Format("2006-01-02") {
		t.Fatalf("archive_date=%v want %s", got.ArchiveDate, old.Format("2006-01-02"))
	}
	if _, ok := st.GetEvent("evt-closed-recent"); ok {
		if e, _ := st.GetEvent("evt-closed-recent"); e.ArchiveDate != nil {
			t.Fatalf("recent closed event should not be archived")
		}
	}
	if e, _ := st.GetEvent("evt-open-old"); e.ArchiveDate != nil {
		t.Fatalf("open event should not be archived")
	}

	// 分页范围
	today, _ := st.ListEventsPage(EventQuery{Scope: "today", Page: 1, PageSize: 10})
	if today.Total != 2 {
		t.Fatalf("today total=%d want 2", today.Total)
	}
	archivePage, _ := st.ListEventsPage(EventQuery{
		Scope: "archive", Date: old.Format("2006-01-02"), Page: 1, PageSize: 10,
	})
	if archivePage.Total != 1 || len(archivePage.Items) != 1 {
		t.Fatalf("archive total=%d items=%d want 1/1", archivePage.Total, len(archivePage.Items))
	}
	all, _ := st.ListEventsPage(EventQuery{Scope: "all", Page: 1, PageSize: 10})
	if all.Total != 3 {
		t.Fatalf("all total=%d want 3", all.Total)
	}

	// 过滤：级别 + 关键字
	filtered, _ := st.ListEventsPage(EventQuery{Scope: "all", Level: "high", Keyword: "旧", Page: 1, PageSize: 10})
	if filtered.Total != 1 {
		t.Fatalf("filtered total=%d want 1", filtered.Total)
	}
	if !strings.Contains(filtered.Items[0].EventID, "archivable") {
		t.Fatalf("filtered item=%s", filtered.Items[0].EventID)
	}
}

func TestSaveGetArchiveJob(t *testing.T) {
	st := NewMemoryStore()
	job, err := st.SaveArchiveJob(domain.ArchiveJob{Period: "2026-08-12", Status: "running"})
	if err != nil {
		t.Fatal(err)
	}
	if job.JobID == "" {
		t.Fatal("job id empty")
	}
	job.Status = "success"
	job.Total = 3
	job.Processed = 3
	if _, err := st.SaveArchiveJob(job); err != nil {
		t.Fatal(err)
	}
	got, ok := st.GetArchiveJob(job.JobID)
	if !ok || got.Status != "success" || got.Total != 3 {
		t.Fatalf("job=%+v ok=%v", got, ok)
	}
}
