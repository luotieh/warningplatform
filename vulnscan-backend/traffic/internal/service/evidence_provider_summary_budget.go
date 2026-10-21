package service

import "vulnscan-backend/traffic/internal/domain"
import "vulnscan-backend/traffic/internal/store"

// Costs are measured at the Reader boundary. A logical query may use multiple
// pages. Retention limits do not imply physical SQL/transport byte limits.
type providerSummaryCost struct {
	ReadCalls         int    `json:"reader_calls"`
	ReturnedRows      int    `json:"returned_rows"`
	ReturnedBytes     int    `json:"returned_summary_bytes"`
	RetainedRows      int    `json:"retained_rows"`
	RetainedBytes     int    `json:"retained_summary_bytes"`
	DiscardedRows     int    `json:"discarded_rows"`
	DiscardedBytes    int    `json:"discarded_summary_bytes"`
	PhysicalSQLCalls  *int   `json:"physical_sql_calls"`
	DatabaseWireBytes *int   `json:"database_wire_bytes"`
	ByteBasis         string `json:"byte_basis"`
}

func providerHistoryBytes(rows []domain.Event) int {
	n := 0
	for _, e := range rows {
		n += store.HistorySummaryBytes(e)
	}
	return n
}

func (c *providerSummaryCost) finish(rows []domain.Event) {
	c.RetainedRows = len(rows)
	c.RetainedBytes = providerHistoryBytes(rows)
	c.DiscardedRows = c.ReturnedRows - c.RetainedRows
	c.DiscardedBytes = c.ReturnedBytes - c.RetainedBytes
	c.ByteBasis = "complete retained Event JSON; Reader-returned rows include sentinel/discards; not database wire bytes"
}
