package service

import (
	"context"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestProviderSummaryBudgetChargesWholeRecordsAndReadDiscards(t *testing.T) {
	at := time.Now().UTC()
	for _, kind := range []string{"observables", "category", "sentinel", "page-discard", "exact-boundary"} {
		t.Run(kind, func(t *testing.T) {
			rows := []domain.Event{{EventID: "first", Context: "{}", CreatedAt: at}, {EventID: "second", Context: "{}", CreatedAt: at.Add(-time.Hour)}}
			limit, bytes := 1, 4<<20
			switch kind {
			case "observables":
				rows[0].Observables = []domain.IOC{{Type: "domain", Value: strings.Repeat("x", 5<<20)}}
			case "category":
				rows[0].Category = strings.Repeat("x", 5<<20)
			case "page-discard":
				bytes = store.HistorySummaryBytes(rows[0]) - 1
			case "exact-boundary":
				rows = rows[:1]
				bytes = store.HistorySummaryBytes(rows[0])
			}
			r := &remainingIndependentHistoryReader{rows: rows}
			cost := &providerSummaryCost{}
			retained, partial, err := providerCandidatesWithinBytes(context.Background(), r, store.HistoryQuery{}, limit, bytes, cost)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if kind == "sentinel" || kind == "exact-boundary" {
				want = 1
			}
			if len(retained) != want || partial != (kind != "exact-boundary") {
				t.Fatal("wrong retained set", retained, partial)
			}
			if cost.ReturnedRows != len(rows) || cost.ReadCalls != 1 || cost.ReturnedBytes != providerHistoryBytes(rows) || cost.RetainedBytes != providerHistoryBytes(retained) || cost.DiscardedBytes != cost.ReturnedBytes-cost.RetainedBytes || cost.DiscardedRows != len(rows)-want {
				t.Fatal("read and retention costs conflated", cost)
			}
			if cost.PhysicalSQLCalls != nil || cost.DatabaseWireBytes != nil {
				t.Fatal("invented DB metrics", cost)
			}
		})
	}
}

func TestProviderSummaryBudgetSharedRemainingIncludesNonContextFields(t *testing.T) {
	c := EvidenceCollection{Options: EvidenceQueryOptions{MaxEvents: 3, Lookback: 24 * time.Hour}, Window: evidence.AnalysisWindow{Start: time.Now().UTC(), End: time.Now().UTC().Add(time.Minute)}, Snapshot: EvidenceSnapshot{Sources: []string{"current"}}, MatchAddresses: []string{"192.0.2.1"}, HistoryCandidates: []domain.Event{{EventID: "primary", Context: "{}", Category: strings.Repeat("x", 4<<20)}}}
	r := &remainingIndependentHistoryReader{}
	a := EvidenceSupplyAudit{}
	if err := collectProviderRelatedHistory(context.Background(), r, &c, &a); err != nil {
		t.Fatal(err)
	}
	if r.calls != 0 || !c.RelatedHistoryTruncated || a.Queries[0].Status != "unavailable" {
		t.Fatal("oversized retained primary did not exhaust shared budget", r.calls, a)
	}
}
