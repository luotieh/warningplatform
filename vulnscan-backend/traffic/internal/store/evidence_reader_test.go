package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

type evidenceReadFixture struct {
	*queryFixture
	opts       driver.TxOptions
	rolledBack bool
	begun      bool
}
type evidenceReadConnector struct{ f *evidenceReadFixture }

func (c evidenceReadConnector) Connect(context.Context) (driver.Conn, error) { return c.f, nil }
func (c evidenceReadConnector) Driver() driver.Driver                        { return fixtureDriver{c.f.queryFixture} }
func (f *evidenceReadFixture) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	f.opts = o
	f.begun = true
	return evidenceReadTx{f}, nil
}
func (f *evidenceReadFixture) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return nil, errors.New("write_forbidden")
}

type evidenceReadTx struct{ f *evidenceReadFixture }

func (t evidenceReadTx) Commit() error   { return errors.New("commit_forbidden") }
func (t evidenceReadTx) Rollback() error { t.f.rolledBack = true; return nil }

func TestEvidenceReaderSQLReadOnlyTransactionAndNoLock(t *testing.T) {
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	f := &evidenceReadFixture{queryFixture: &queryFixture{rows: [][]driver.Value{fixtureEvent("saved-event", "{}", at, at)}}}
	db := sql.OpenDB(evidenceReadConnector{f})
	defer db.Close()
	reader, closeRead, err := NewEvidenceReadTransaction(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !f.begun || !f.opts.ReadOnly || f.opts.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		t.Fatal("unsafe transaction", f.opts)
	}
	e, ok, err := reader.EvidenceEvent(context.Background(), "saved-event")
	if err != nil || !ok || e.EventID != "saved-event" {
		t.Fatal(e, ok, err)
	}
	if len(f.queries) != 1 || strings.Contains(strings.ToUpper(f.queries[0]), "FOR UPDATE") || !strings.Contains(f.queries[0], "WHERE event_id=?") {
		t.Fatal("unbounded or locking read", f.queries)
	}
	if err = closeRead(); err != nil || !f.rolledBack {
		t.Fatal("not rolled back", err)
	}
}

func TestEvidenceReaderMissingAndCanceledAreDistinct(t *testing.T) {
	f := &queryFixture{}
	db := sql.OpenDB(f)
	defer db.Close()
	s := NewMySQLStore(db)
	_, ok, err := s.EvidenceEvent(context.Background(), "missing")
	if ok || err != nil {
		t.Fatal(ok, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, ok, err = s.EvidenceEvent(ctx, "missing")
	if ok || !errors.Is(err, context.Canceled) {
		t.Fatal(ok, err)
	}
}

func TestEvidenceReaderMemoryFixedRevisionWatermark(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	h, err := s.InsertHit(ctx, Hit{ID: "h", DedupKey: "h", EventID: "e", OccurredAt: at, Raw: []byte(`{"app":{"http_method":"GET"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	rw, err := s.InsertHitRevision(ctx, h.ID, 1, []byte(`{"app":{"http_method":"POST"}}`))
	if err != nil {
		t.Fatal(err)
	}
	q := HitQuery{Sources: []string{"e"}, Watermark: h.Sequence, Limit: 200}
	old, err := s.SnapshotPage(ctx, q, 0, 1024, 1024)
	if err != nil || len(old) != 1 || strings.Contains(string(old[0].Raw), "POST") {
		t.Fatal("late revision leaked", err)
	}
	fresh, err := s.SnapshotPage(ctx, q, rw, 1024, 1024)
	if err != nil || len(fresh) != 1 || !strings.Contains(string(fresh[0].Raw), "POST") {
		t.Fatal("effective revision missing", err)
	}
	if _, err = s.SnapshotPage(ctx, q, rw, 1, 1); err == nil {
		t.Fatal("oversize silently skipped")
	}
}
