package service

import (
	"context"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Event-time history keeps its exact primary query. Other evidence needs saved
// associations with other IOCs or assets. Fetch only summaries, sharing the
// existing event/context-byte caps; never expand historical packets.
func collectProviderRelatedHistory(ctx context.Context, r store.EvidenceReader, c *EvidenceCollection, a *EvidenceSupplyAudit) error {
	w := evidence.AnalysisWindow{Start: c.Window.Start.Add(-c.Options.Lookback), End: c.Window.Start}
	remaining := c.Options.MaxEvents - len(c.HistoryCandidates)
	bytes := 4 << 20
	exclude := append([]string(nil), c.Snapshot.Sources...)
	for _, e := range c.HistoryCandidates {
		exclude = append(exclude, e.EventID)
		bytes -= store.HistorySummaryBytes(e)
	}
	exclude = uniqueSortedStrings(exclude)
	q := EvidenceProviderQuery{ID: "Q:history-related", Family: "history", Rules: []string{"F_HIST_INFRA_PERSISTENCE", "F_HIST_MULTI_IOC_SIEGE"},
		Provider: "HistoryDataProvider", Method: "HistoryCandidates(summary; related asset OR IOC)",
		Keys:   map[string]any{"addresses": c.MatchAddresses, "iocs": c.MatchIOCs, "exclude": exclude, "require_asset_ioc": false, "summary_only": true, "shared_remaining_summary_bytes": bytes},
		Window: w, Budget: remaining, Status: "completed", Coverage: "saved_event_associations_only_not_network_coverage"}
	started := time.Now()
	if remaining <= 0 || bytes <= 0 || len(exclude) > 256 || c.HistoryTruncated {
		c.RelatedHistoryTruncated = true
		q.Status = "unavailable"
		q.Reason = "shared_history_budget_or_exclusion_limit_exhausted"
	} else if len(c.MatchAddresses)+len(c.MatchIOCs) == 0 {
		q.Status = "unavailable"
		q.Reason = "asset_and_ioc_identity_unresolved"
	} else {
		var err error
		cost := &providerSummaryCost{}
		c.RelatedHistoryCandidates, c.RelatedHistoryTruncated, err = providerCandidatesWithinBytes(ctx, r, store.HistoryQuery{Start: w.Start, End: w.End, Addresses: c.MatchAddresses, IOCs: c.MatchIOCs, ExcludeIDs: exclude, SummaryOnly: true}, remaining, bytes, cost)
		q.Keys.(map[string]any)["summary_cost"] = cost
		q.Rows = len(c.RelatedHistoryCandidates)
		if err != nil {
			c.RelatedHistoryTruncated = true
			q.Status = "failed"
			q.Reason = "related_summary_query_failed"
		}
		if c.RelatedHistoryTruncated && q.Reason == "" {
			q.Reason = "shared_history_candidate_or_byte_budget_exceeded"
		}
	}
	q.ElapsedMS = time.Since(started).Milliseconds()
	a.Queries = append(a.Queries, q)
	if q.Reason != "" {
		a.Diagnostics = append(a.Diagnostics, q.ID+":"+q.Reason)
	}
	return ctx.Err()
}

// Related rows have their own list so they cannot alter event-time sample counts
// or the primary query's completeness. Device provenance is retained, including
// independently registered assets observed by a different saved sensor.
func assembleProviderRelatedHistory(c EvidenceCollection, primary ReportHistory) []ReportHistoryRow {
	out := []ReportHistoryRow{}
	seen := map[string]bool{}
	for _, row := range primary.Rows {
		seen[row.EventID] = true
	}
	for _, id := range c.Snapshot.Sources {
		seen[id] = true
	}
	// Reuse primary candidates rejected for the event-time device contract.
	// They can still prove a saved infrastructure association; no second read.
	candidates := append(append([]domain.Event(nil), c.HistoryCandidates...), c.RelatedHistoryCandidates...)
	for _, e := range candidates {
		if e.EventID == "" || seen[e.EventID] {
			continue
		}
		m := decodeEventContext(e.Context)
		device := asString(m["device_id"])
		first, e1 := time.Parse(time.RFC3339Nano, asString(m["first_time"]))
		last, e2 := time.Parse(time.RFC3339Nano, asString(m["last_time"]))
		if device == "" || e1 != nil || e2 != nil || last.Before(first) || first.Before(primary.Start) || !last.Before(primary.End) {
			continue
		}
		ids, addresses := []string{}, []string{}
		for _, key := range []string{"src_ip", "dst_ip"} {
			address := asString(m[key])
			if id, ok := registeredSnapshotAsset(c.Assets, address); ok {
				ids = append(ids, id)
				addresses = append(addresses, address)
			}
		}
		ids = uniqueSortedStrings(ids)
		if len(ids) != 1 {
			continue
		}
		matched := []domain.IOC{}
		for _, ioc := range historyIOCs(e, m) {
			for _, address := range addresses {
				if providerHistoryRelation(m, store.HistoryRelation{Address: address, IOC: ioc}) {
					matched = append(matched, ioc)
					break
				}
			}
		}
		unique := []domain.IOC{}
		seenIOCs := map[string]bool{}
		for _, ioc := range matched {
			key := ioc.Type + ":" + ioc.Value
			if !seenIOCs[key] {
				seenIOCs[key] = true
				unique = append(unique, ioc)
			}
		}
		matched = unique
		if len(matched) != 1 {
			continue
		}
		related := false
		for _, address := range addresses {
			for _, current := range c.MatchAddresses {
				related = related || address == current
			}
		}
		for _, current := range c.MatchIOCs {
			related = related || matched[0].Type == current.Type && matched[0].Value == current.Value
		}
		if !related {
			continue
		}
		seen[e.EventID] = true
		out = append(out, ReportHistoryRow{EventID: e.EventID, DeviceID: device, First: first, Last: last, AssetIDs: ids, AllAssetIDs: ids,
			IOCs: matched, ActivityIOCs: matched, Application: nestedMap(m, "app"), SourceAddress: asString(m["src_ip"]), DestinationAddress: asString(m["dst_ip"]),
			Relation: "related_asset_or_ioc", ActivityType: e.Category, Adjudication: "unreviewed"})
	}
	return out
}

func providerRelatedHistoryForScope(row ReportHistoryRow, scope evidence.Scope, targets []domain.IOC) bool {
	if len(row.AllAssetIDs) != 1 {
		return false
	}
	if row.AllAssetIDs[0] == scope.AssetID && row.DeviceID == scope.DeviceID {
		return true
	}
	// Cross-asset infrastructure history must still match this endpoint's IOC.
	for _, ioc := range row.IOCs {
		for _, target := range targets {
			if ioc.Type == target.Type && ioc.Value == target.Value {
				return true
			}
		}
	}
	return false
}
