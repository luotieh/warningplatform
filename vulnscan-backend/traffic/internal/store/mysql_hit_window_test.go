package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Model the observed MySQL DATETIME(6) parameter conversion. Unlike a
// MemoryStore, the database discards sub-microsecond digits before comparison.
type mysqlHitWindowFixture struct {
	queryFixture
	hits []Hit
}

type mysqlHitWindowConnector struct{ fixture *mysqlHitWindowFixture }

func (c mysqlHitWindowConnector) Connect(context.Context) (driver.Conn, error) {
	return c.fixture, nil
}
func (c mysqlHitWindowConnector) Driver() driver.Driver {
	return fixtureDriver{&c.fixture.queryFixture}
}

func (f *mysqlHitWindowFixture) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	arg := func(fragment string) (int, bool) {
		at := strings.Index(query, fragment)
		return strings.Count(query[:max(0, at)], "?"), at >= 0
	}
	var from, to, after time.Time
	var afterID string
	if i, ok := arg("occurred_at>=?"); ok {
		from = args[i].Value.(time.Time).Truncate(time.Microsecond)
	}
	if i, ok := arg("occurred_at<?"); ok {
		to = args[i].Value.(time.Time).Truncate(time.Microsecond)
	}
	if i, ok := arg("occurred_at>?"); ok {
		after = args[i].Value.(time.Time).Truncate(time.Microsecond)
		afterID = args[i+2].Value.(string)
	}
	limit := int(args[len(args)-1].Value.(int64))
	byteQuery := strings.Contains(query, "OCTET_LENGTH")
	rows := [][]driver.Value{}
	for _, hit := range f.hits {
		if !from.IsZero() && hit.OccurredAt.Before(from) || !to.IsZero() && !hit.OccurredAt.Before(to) {
			continue
		}
		if !after.IsZero() && (hit.OccurredAt.Before(after) || hit.OccurredAt.Equal(after) && hit.ID <= afterID) {
			continue
		}
		if byteQuery {
			rows = append(rows, []driver.Value{hit.ID, int64(len(hit.Raw)), int64(0)})
		} else {
			rows = append(rows, []driver.Value{hit.Sequence, hit.ID, hit.DedupKey, hit.Identity, hit.AggregateKey, hit.EventID, hit.OccurredAt, hit.ReceivedAt, []byte(hit.Raw)})
		}
		if len(rows) == limit {
			break
		}
	}
	columns := strings.Split(hitColumns, ",")
	if byteQuery {
		columns = []string{"hit_id", "base_bytes", "revision_bytes"}
	}
	return &snapshotRows{fixtureRows: fixtureRows{rows: rows}, columns: columns}, nil
}

func checkMySQLHitWindow(t *testing.T, hits []Hit, from, to time.Time, want []string) {
	t.Helper()
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].OccurredAt.Equal(hits[j].OccurredAt) {
			return hits[i].ID < hits[j].ID
		}
		return hits[i].OccurredAt.Before(hits[j].OccurredAt)
	})
	f := &mysqlHitWindowFixture{hits: hits}
	db := sql.OpenDB(mysqlHitWindowConnector{f})
	defer db.Close()
	st := NewMySQLStore(db)
	for _, method := range []string{"HitPage", "SnapshotPage"} {
		t.Run(method, func(t *testing.T) {
			q := HitQuery{Sources: []string{hits[0].EventID}, Watermark: 1 << 30, From: from, To: to, Limit: 5}
			got := []string{}
			for {
				var page []Hit
				var err error
				if method == "HitPage" {
					page, err = st.HitPage(context.Background(), q)
				} else {
					page, err = st.SnapshotPage(context.Background(), q, 0, 2<<20, 1<<20)
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(page) == 0 {
					break
				}
				for _, hit := range page {
					if hit.OccurredAt.Before(from) || !hit.OccurredAt.Before(to) {
						t.Fatalf("returned hit outside requested [from,to): %s", hit.ID)
					}
					got = append(got, hit.ID)
				}
				tail := page[len(page)-1]
				if tail.OccurredAt.Equal(q.AfterTime) && tail.ID == q.AfterID {
					t.Fatal("pagination stalled")
				}
				q.AfterTime, q.AfterID = tail.OccurredAt, tail.ID
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestMySQLHitWindowMicrosecondPrecision(t *testing.T) {
	at := time.Date(2026, 10, 20, 4, 48, 0, 691677000, time.UTC)
	hits := []Hit{
		{ID: "before", EventID: "event", OccurredAt: at.Add(-time.Microsecond), Raw: json.RawMessage(`{}`)},
		{ID: "at", EventID: "event", OccurredAt: at, Raw: json.RawMessage(`{}`)},
		{ID: "next-a", EventID: "event", OccurredAt: at.Add(time.Microsecond), Raw: json.RawMessage(`{}`)},
		{ID: "next-b", EventID: "event", OccurredAt: at.Add(time.Microsecond), Raw: json.RawMessage(`{}`)},
		{ID: "end", EventID: "event", OccurredAt: at.Add(2 * time.Microsecond), Raw: json.RawMessage(`{}`)},
	}
	for _, tc := range []struct {
		name     string
		from, to time.Time
		want     []string
	}{
		{"include_last_plus_nanosecond", at, at.Add(time.Nanosecond), []string{"at"}},
		{"aligned_upper_stays_exclusive", at, at.Add(time.Microsecond), []string{"at"}},
		{"fractional_lower_excludes_previous_tick", at.Add(time.Nanosecond), at.Add(2 * time.Microsecond), []string{"next-a", "next-b"}},
		{"empty_submicrosecond_window", at.Add(time.Nanosecond), at.Add(999 * time.Nanosecond), []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) { checkMySQLHitWindow(t, hits, tc.from, tc.to, tc.want) })
	}
	last := time.Date(2026, 10, 20, 23, 59, 59, 999999000, time.FixedZone("Beijing", 8*3600))
	checkMySQLHitWindow(t, []Hit{
		{ID: "last", EventID: "event", OccurredAt: last, Raw: json.RawMessage(`{}`)},
		{ID: "midnight", EventID: "event", OccurredAt: last.Add(time.Microsecond), Raw: json.RawMessage(`{}`)},
	}, last, last.Add(time.Nanosecond), []string{"last"})
}

// Replay the saved production rows through the actual MySQL query/scanner
// paths without a live connection or changes to the source archives.
func TestMySQLHitWindowFrozenThreeArchives(t *testing.T) {
	dir := os.Getenv("PROVIDER_FROZEN_THREE_DIR")
	if dir == "" {
		t.Skip("optional local three-chain archive")
	}
	data, err := os.ReadFile(filepath.Join(dir, "capture-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Events []struct {
			EventID string `json:"event_id"`
		} `json:"events"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Events) != 3 {
		t.Fatal("expected three saved chains")
	}
	for _, event := range manifest.Events {
		t.Run(event.EventID, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, event.EventID, "platform-rows", "current-hits.json"))
			if err != nil {
				t.Fatal(err)
			}
			var rows []struct {
				Hit
				StoredRaw string `json:"stored_raw_json"`
			}
			if err := json.Unmarshal(data, &rows); err != nil {
				t.Fatal(err)
			}
			hits := []Hit{}
			for _, row := range rows {
				row.Raw = json.RawMessage(row.StoredRaw)
				hits = append(hits, row.Hit)
			}
			sort.Slice(hits, func(i, j int) bool {
				if hits[i].OccurredAt.Equal(hits[j].OccurredAt) {
					return hits[i].ID < hits[j].ID
				}
				return hits[i].OccurredAt.Before(hits[j].OccurredAt)
			})
			want := []string{}
			for _, hit := range hits {
				want = append(want, hit.ID)
			}
			checkMySQLHitWindow(t, hits, hits[0].OccurredAt, hits[len(hits)-1].OccurredAt.Add(time.Nanosecond), want)
		})
	}
}
