package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"testing"
)

func TestHitRevisionBatchPreservesWatermarkAndSourceOrder(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	_, err := st.InsertHitRevision(ctx, "a", 2, json.RawMessage(`{"revision":2}`))
	if err != nil {
		t.Fatal(err)
	}
	watermark, err := st.InsertHitRevision(ctx, "a", 1, json.RawMessage(`{"revision":1}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.InsertHitRevision(ctx, "a", 3, json.RawMessage(`{"revision":3}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.InsertHitRevision(ctx, "other", 1, json.RawMessage(`{"outside":true}`))
	if err != nil {
		t.Fatal(err)
	}
	batch, err := st.HitRevisions(ctx, []string{"a", "absent", "a"}, watermark)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 1 || string(batch["a"]) != `{"revision":2}` {
		t.Fatalf("wrong batch revision: %v", batch)
	}
	single, err := st.HitRevision(ctx, "a", watermark)
	if err != nil || string(single) != string(batch["a"]) {
		t.Fatal("batch changed single-hit semantics")
	}
	batch["a"][0] = 'x'
	again, _ := st.HitRevisions(ctx, []string{"a"}, watermark)
	if string(again["a"]) != `{"revision":2}` {
		t.Fatal("returned bytes alias stored revision")
	}
	if _, err := st.HitRevisions(ctx, make([]string, 501), watermark); err == nil {
		t.Fatal("oversized query accepted")
	}
}

type revisionQueryFixture struct {
	queryFixture
	args []driver.NamedValue
}

func (f *revisionQueryFixture) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	f.queries = append(f.queries, q)
	f.args = args
	return &revisionFixtureRows{fixtureRows: fixtureRows{rows: f.rows}}, nil
}

type revisionFixtureRows struct{ fixtureRows }

func (r *revisionFixtureRows) Columns() []string { return []string{"hit_id", "raw_json"} }

type revisionFixtureConnector struct{ fixture *revisionQueryFixture }

func (c revisionFixtureConnector) Connect(context.Context) (driver.Conn, error) {
	return c.fixture, nil
}
func (c revisionFixtureConnector) Driver() driver.Driver {
	return fixtureDriver{&c.fixture.queryFixture}
}

func TestMySQLHitRevisionBatchUsesOneBoundedQuery(t *testing.T) {
	f := &revisionQueryFixture{queryFixture: queryFixture{rows: [][]driver.Value{{"a", []byte(`{"revision":2}`)}, {"b", []byte(`{"revision":1}`)}}}}
	db := sql.OpenDB(revisionFixtureConnector{f})
	defer db.Close()
	st := NewMySQLStore(db)
	result, err := st.HitRevisions(context.Background(), []string{"a", "b", "missing"}, 17)
	if err != nil || len(result) != 2 {
		t.Fatalf("query/scanner error: %v %v", err, result)
	}
	if len(f.queries) != 1 || len(f.args) != 4 || f.args[3].Value != int64(17) {
		t.Fatalf("N+1 or missing watermark: %v %v", f.queries, f.args)
	}
	for _, part := range []string{"MAX(source_revision)", "hit_id IN (?,?,?)", "sequence<=?", "GROUP BY hit_id"} {
		if !strings.Contains(f.queries[0], part) {
			t.Fatalf("unsafe query missing %s", part)
		}
	}
	st.HitRevisions(context.Background(), nil, 17)
	st.HitRevisions(context.Background(), []string{"a"}, 0)
	if len(f.queries) != 1 {
		t.Fatal("empty/zero-watermark query touched database")
	}
	if _, err := st.HitRevisions(context.Background(), make([]string, 501), 17); err == nil {
		t.Fatal("batch query limit ignored")
	}
}
