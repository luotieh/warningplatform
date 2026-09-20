package store

import (
	"context"
	"encoding/json"
	"time"
)

// Aggregation records use immutable hit ownership. A snapshot names the original
// event IDs and a committed high-water mark, so late arrivals and merges never
// change the meaning of an existing cursor or report.
type Hit struct {
	Sequence     int64           `json:"sequence"`
	ID           string          `json:"hit_id"`
	DedupKey     string          `json:"dedup_key"`
	Identity     string          `json:"identity_digest"`
	AggregateKey string          `json:"aggregate_key"`
	EventID      string          `json:"origin_event_id"`
	OccurredAt   time.Time       `json:"occurred_at"`
	ReceivedAt   time.Time       `json:"received_at"`
	Raw          json.RawMessage `json:"raw"`
}

type HitQuery struct {
	Sources   []string
	Watermark int64
	AfterTime time.Time
	AfterID   string
	From      time.Time
	To        time.Time
	ID        string
	Limit     int
}

type AggregateRecord struct {
	Kind  string          `json:"kind"`
	Key   string          `json:"key"`
	Group string          `json:"group"`
	Value json.RawMessage `json:"value"`
}

type AggregationStore interface {
	LockAggregationKey(context.Context, string) error
	// The callback must use tx exclusively and must not perform network I/O.
	AggregationTransaction(context.Context, string, func(Store) error) error
	AggregateRecord(context.Context, string, string) (AggregateRecord, bool, error)
	PutAggregateRecord(context.Context, AggregateRecord) error
	AggregateRecords(context.Context, string, string, int) ([]AggregateRecord, error)
	FindHit(context.Context, string) (Hit, bool, error)
	InsertHit(context.Context, Hit) (Hit, error)
	HitPage(context.Context, HitQuery) ([]Hit, error)
	InsertHitRevision(context.Context, string, int64, json.RawMessage) (int64, error)
	HitRevision(context.Context, string, int64) (json.RawMessage, error)
}

const AggregationSchema = `
CREATE TABLE IF NOT EXISTS traffic_aggregation_migrations (
 version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 applied_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS traffic_aggregation_locks (
 lock_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS traffic_aggregation_records (
 kind VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 record_key VARCHAR(160) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 group_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 value_json LONGTEXT NOT NULL,
 PRIMARY KEY(kind,record_key), KEY idx_aggregation_group(kind,group_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS traffic_event_hits (
 sequence BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
 hit_id CHAR(68) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 dedup_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 identity_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 aggregate_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 origin_event_id VARCHAR(128) NOT NULL,
 occurred_at DATETIME(6) NOT NULL,
 received_at DATETIME(6) NOT NULL,
 raw_json LONGTEXT NOT NULL,
 UNIQUE KEY uq_hit_id(hit_id), UNIQUE KEY uq_hit_dedup(dedup_key),
 KEY idx_hit_event_time(origin_event_id,occurred_at,hit_id),
 KEY idx_hit_group_time(aggregate_key,occurred_at,hit_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS traffic_hit_revisions (
 sequence BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
 hit_id CHAR(68) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 source_revision BIGINT NOT NULL,
 raw_json LONGTEXT NOT NULL,
 UNIQUE KEY uq_hit_revision(hit_id,source_revision),
 KEY idx_hit_revision_sequence(hit_id,sequence)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT IGNORE INTO traffic_aggregation_migrations(version) VALUES ('20260918_aggregation_v2');
`
