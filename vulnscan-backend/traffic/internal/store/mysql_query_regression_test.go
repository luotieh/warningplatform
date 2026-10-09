package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// Exercise the real MySQL query/scanner path without modifying a database.
type queryFixture struct {
	rows    [][]driver.Value
	queries []string
}

func (f *queryFixture) Connect(context.Context) (driver.Conn, error) { return f, nil }
func (f *queryFixture) Driver() driver.Driver                        { return fixtureDriver{f} }

type fixtureDriver struct{ f *queryFixture }

func (d fixtureDriver) Open(string) (driver.Conn, error) { return d.f, nil }
func (f *queryFixture) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (f *queryFixture) Close() error              { return nil }
func (f *queryFixture) Begin() (driver.Tx, error) { return nil, errors.New("unexpected write") }
func (f *queryFixture) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	f.queries = append(f.queries, q)
	return &fixtureRows{rows: f.rows}, nil
}

type fixtureRows struct {
	rows [][]driver.Value
	pos  int
}

func (r *fixtureRows) Columns() []string { return strings.Split(eventSelectCols, ", ") }
func (r *fixtureRows) Close() error      { return nil }
func (r *fixtureRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.pos])
	r.pos++
	return nil
}
func fixtureEvent(id string, ctx string, created, archive time.Time) []driver.Value {
	return []driver.Value{int64(1), id, "event", "", "", ctx, "source", "high", "", "", int64(1), []byte("[]"), created, created, "", "", "", nil, "", int64(1), true, nil, nil, archive}
}
func TestMySQLTimeQueryFiltersArchiveAndOffsetsBeforePagination(t *testing.T) {
	start := time.Date(2026, 10, 8, 0, 0, 0, 0, time.FixedZone("Beijing", 8*3600))
	end := start.AddDate(0, 0, 1)
	f := &queryFixture{rows: [][]driver.Value{
		fixtureEvent("before", `{"first_time":"2026-10-07T23:30:00+08:00"}`, start, start),
		fixtureEvent("offset", `{"first_time":"2026-10-08T00:05:00+08:00"}`, start.AddDate(0, 0, -3), start),
		fixtureEvent("utc", `{"occurrence_time":"2026-10-07T16:05:00Z"}`, start.AddDate(0, 0, -3), start),
		fixtureEvent("at-end", `{"first_time":"2026-10-09T00:00:00+08:00"}`, start, start),
	}}
	db := sql.OpenDB(f)
	defer db.Close()
	st := &MySQLStore{db: db}
	q := EventQuery{Scope: "today", StartTime: &start, EndTime: &end, Page: 2, PageSize: 1}
	page, err := st.ListEventsPage(q)
	if err != nil || page.Total != 2 || len(page.Items) != 1 || page.Items[0].EventID != "utc" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	all, err := st.ListEventsMatching(q)
	if err != nil || len(all) != 2 {
		t.Fatalf("matching=%+v err=%v", all, err)
	}
	for _, q := range f.queries {
		if strings.Contains(q, "archive_date IS NULL") || strings.Contains(q, "STR_TO_DATE") || strings.Contains(q, "LIMIT") {
			t.Fatalf("query hides/truncates events before time filtering: %s", q)
		}
	}
}
func TestMySQLAssetReportQueryIncludesLegacyArchive(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	f := &queryFixture{rows: [][]driver.Value{fixtureEvent("legacy", `{"last_time":"2026-10-08T00:05:00+08:00"}`, start.AddDate(0, -1, 0), start)}}
	db := sql.OpenDB(f)
	defer db.Close()
	st := &MySQLStore{db: db}
	got := st.ListEventsByTargetIP("10.0.0.8", start, end)
	if len(got) != 1 {
		t.Fatalf("legacy archive missing: %v", got)
	}
	for _, q := range f.queries {
		if strings.Contains(q, "last_seen_at IS NOT NULL") || strings.Contains(q, "archive_date IS NULL") || strings.Contains(q, "LIMIT") {
			t.Fatalf("query excludes legacy archive: %s", q)
		}
	}
}
