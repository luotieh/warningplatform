package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"
)

type snapshotQueryFixture struct {
	queryFixture
	oversized bool
	args      [][]driver.NamedValue
}
type snapshotRows struct {
	fixtureRows
	columns []string
}

func (r *snapshotRows) Columns() []string { return r.columns }
func (f *snapshotQueryFixture) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	f.queries = append(f.queries, q)
	f.args = append(f.args, args)
	if strings.Contains(q, "OCTET_LENGTH") {
		size := int64(10)
		if f.oversized {
			size = 1000
		}
		return &snapshotRows{fixtureRows: fixtureRows{rows: [][]driver.Value{{"a", size, int64(10)}, {"b", int64(10), int64(10)}}}, columns: []string{"id", "base", "revision"}}, nil
	}
	if strings.Contains(q, "SELECT r.hit_id") {
		return &snapshotRows{fixtureRows: fixtureRows{rows: [][]driver.Value{{"a", []byte(`{"rev":2}`)}}}, columns: []string{"id", "raw"}}, nil
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return &snapshotRows{fixtureRows: fixtureRows{rows: [][]driver.Value{{int64(3), "a", "dedup", "identity", "agg", "event", at, at, []byte(`{"base":1}`)}}}, columns: strings.Split(hitColumns, ",")}, nil
}

type snapshotConnector struct{ f *snapshotQueryFixture }

func (c snapshotConnector) Connect(context.Context) (driver.Conn, error) { return c.f, nil }
func (c snapshotConnector) Driver() driver.Driver                        { return fixtureDriver{&c.f.queryFixture} }

func TestMySQLSnapshotBytePagePreservesRevisionAndPrefix(t *testing.T) {
	f := &snapshotQueryFixture{}
	db := sql.OpenDB(snapshotConnector{f})
	defer db.Close()
	q := HitQuery{Sources: []string{"event"}, Watermark: 7, Limit: 500, AfterTime: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), AfterID: "previous"}
	page, err := NewMySQLStore(db).SnapshotPage(context.Background(), q, 17, 25, 25)
	if err != nil || len(page) != 1 || string(page[0].Raw) != `{"rev":2}` {
		t.Fatal(page, err)
	}
	if len(f.queries) != 3 || f.args[0][0].Value != int64(17) || f.args[1][len(f.args[1])-1].Value != int64(1) {
		t.Fatal("raw read was not bounded to prefix", f.args)
	}
	for _, part := range []string{"OCTET_LENGTH", "source_revision DESC", "h.sequence<=?", "h.occurred_at>?", "h.hit_id>?"} {
		if !strings.Contains(f.queries[0], part) {
			t.Fatal("missing frozen query constraint", part)
		}
	}
}

func TestMySQLSnapshotOversizedRowIsNeverSkipped(t *testing.T) {
	f := &snapshotQueryFixture{oversized: true}
	db := sql.OpenDB(snapshotConnector{f})
	defer db.Close()
	_, err := NewMySQLStore(db).SnapshotPage(context.Background(), HitQuery{Sources: []string{"event"}, Watermark: 7, Limit: 500}, 17, 25, 25)
	if err == nil || !strings.Contains(err.Error(), "snapshot_row_budget_exceeded:a") || len(f.queries) != 1 {
		t.Fatal("oversized raw was read or silently skipped", err, f.queries)
	}
}
