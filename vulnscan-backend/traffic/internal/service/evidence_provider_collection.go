package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// The domain providers share a narrow, read-only Store surface. Only the
// orchestrator plans queries; rules never reach the database.
type EventDataProvider struct{ Reader store.EvidenceReader }
type AssetDataProvider struct{ Reader store.EvidenceReader }
type TrafficDataProvider struct{ Reader store.EvidenceReader }
type HistoryDataProvider struct{ Reader store.EvidenceReader }
type GroupDataProvider struct{ Reader store.EvidenceReader }
type ContextDataProvider struct{ Reader store.EvidenceReader }

func (p EventDataProvider) Load(ctx context.Context, id string) (domain.Event, EvidenceSnapshot, error) {
	e, ok, err := p.Reader.EvidenceEvent(ctx, id)
	if err != nil {
		return e, EvidenceSnapshot{}, err
	}
	if !ok {
		return e, EvidenceSnapshot{}, fmt.Errorf("event_not_found")
	}
	r, ok, err := p.Reader.AggregateRecord(ctx, "segment", id)
	if err != nil {
		return e, EvidenceSnapshot{}, err
	}
	if !ok {
		return e, EvidenceSnapshot{}, fmt.Errorf("published_segment_missing")
	}
	var seg EventSegment
	if err = json.Unmarshal(r.Value, &seg); err != nil {
		return e, EvidenceSnapshot{}, err
	}
	if seg.EventID != id || seg.Published <= 0 || seg.Disabled {
		return e, EvidenceSnapshot{}, fmt.Errorf("published_segment_invalid")
	}
	r, ok, err = p.Reader.AggregateRecord(ctx, "snapshot", snapshotKey(id, seg.Published))
	if err != nil {
		return e, EvidenceSnapshot{}, err
	}
	if !ok {
		return e, EvidenceSnapshot{}, fmt.Errorf("published_snapshot_missing")
	}
	var s EvidenceSnapshot
	err = json.Unmarshal(r.Value, &s)
	if err == nil && (s.EventID != id || s.Version != seg.Published || len(s.Sources) == 0 || s.Count < 0 || s.Watermark < 0 || s.RevisionWatermark < 0) {
		err = fmt.Errorf("published_snapshot_invalid")
	}
	if len(s.Sources) > 256 {
		return e, s, fmt.Errorf("snapshot_source_budget_exceeded")
	}
	seen := map[string]bool{}
	for _, source := range s.Sources {
		if source == "" || seen[source] {
			return e, s, fmt.Errorf("snapshot_source_identity_invalid")
		}
		seen[source] = true
	}
	return e, s, err
}
func (p AssetDataProvider) Load(ctx context.Context, limit int) ([]domain.Asset, error) {
	return p.Reader.EvidenceAssets(ctx, limit)
}
func (p TrafficDataProvider) Load(ctx context.Context, s EvidenceSnapshot, w evidence.AnalysisWindow, o EvidenceQueryOptions) ([]store.Hit, error) {
	q := store.HitQuery{Sources: s.Sources, Watermark: s.Watermark, From: w.Start, To: w.End, Limit: 200}
	rows := []store.Hit{}
	seen := map[string]bool{}
	var bytes int64
	for {
		page, err := p.Reader.SnapshotPage(ctx, q, s.RevisionWatermark, 2<<20, 1<<20)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		for _, h := range page {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			bytes += int64(len(h.Raw))
			if len(rows) >= o.MaxHits {
				return nil, fmt.Errorf("hit_budget_exceeded")
			}
			if bytes > o.MaxBytes {
				return nil, fmt.Errorf("byte_budget_exceeded")
			}
			if seen[h.ID] || h.ID == "" || h.OccurredAt.Before(w.Start) || !h.OccurredAt.Before(w.End) || h.Sequence > s.Watermark {
				return nil, fmt.Errorf("hit_source_or_window_mismatch")
			}
			found := false
			for _, id := range s.Sources {
				found = found || id == h.EventID
			}
			if !found {
				return nil, fmt.Errorf("hit_event_membership_mismatch")
			}
			seen[h.ID] = true
			rows = append(rows, h)
		}
		tail := page[len(page)-1]
		if !q.AfterTime.IsZero() && (tail.OccurredAt.Before(q.AfterTime) || tail.OccurredAt.Equal(q.AfterTime) && tail.ID <= q.AfterID) {
			return nil, fmt.Errorf("hit_cursor_stalled")
		}
		q.AfterTime, q.AfterID = tail.OccurredAt, tail.ID
	}
	return rows, nil
}
func providerCandidates(ctx context.Context, r store.EvidenceReader, q store.HistoryQuery, limit int) ([]domain.Event, bool, error) {
	return providerCandidatesWithinBytes(ctx, r, q, limit, 4<<20)
}

func providerCandidatesWithinBytes(ctx context.Context, r store.EvidenceReader, q store.HistoryQuery, limit, maxBytes int, costs ...*providerSummaryCost) (rows []domain.Event, truncated bool, resultErr error) {
	rows = []domain.Event{}
	cost := &providerSummaryCost{}
	if len(costs) > 0 && costs[0] != nil {
		cost = costs[0]
	}
	defer func() { cost.finish(rows) }()
	seen := map[string]bool{}
	var bytes int
	for len(rows) <= limit {
		q.Limit = 201
		if remaining := limit + 1 - len(rows); remaining < q.Limit {
			q.Limit = remaining
		}
		cost.ReadCalls++
		page, err := r.HistoryCandidates(ctx, q)
		cost.ReturnedRows += len(page)
		cost.ReturnedBytes += providerHistoryBytes(page)
		if err != nil {
			return nil, false, err
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			bytes += store.HistorySummaryBytes(e)
			if bytes > maxBytes {
				return rows, true, nil
			}
			if seen[e.EventID] {
				return nil, false, fmt.Errorf("history_cursor_stalled")
			}
			seen[e.EventID] = true
			rows = append(rows, e)
		}
		tail := page[len(page)-1]
		q.BeforeTime = tail.CreatedAt
		if tail.LastSeenAt != nil {
			q.BeforeTime = *tail.LastSeenAt
		}
		q.AfterID = tail.EventID
		if len(page) < q.Limit {
			break
		}
	}
	truncated = len(rows) > limit
	if truncated {
		rows = rows[:limit]
	}
	return rows, truncated, nil
}
func (p HistoryDataProvider) Load(ctx context.Context, q store.HistoryQuery, limit int) ([]domain.Event, bool, error) {
	return providerCandidates(ctx, p.Reader, q, limit)
}
func (p GroupDataProvider) Load(ctx context.Context, q store.HistoryQuery, limit int) ([]domain.Event, bool, error) {
	return providerCandidates(ctx, p.Reader, q, limit)
}

// Context records cross the collection boundary unchanged. Validation and
// conversion belong to the preprocessor, not the platform query adapter.
func (p ContextDataProvider) Load(ctx context.Context) (store.AggregateRecord, bool, error) {
	return p.Reader.AggregateRecord(ctx, "evidence_sources", "active")
}
func (p ContextDataProvider) LoadSupplemental(ctx context.Context, s EvidenceSnapshot) (store.AggregateRecord, bool, error) {
	return p.Reader.AggregateRecord(ctx, "evidence_inputs", snapshotKey(s.EventID, s.Version))
}

func CollectEvidenceFromPlatform(ctx context.Context, r store.EvidenceReader, id string, options EvidenceQueryOptions) (c EvidenceCollection, err error) {
	a := EvidenceSupplyAudit{}
	started := time.Now()
	a = EvidenceSupplyAudit{Version: "evidence-data-provider-1.1-loss-audit", EventID: id, ReadOnly: true, Consistency: "published immutable snapshot watermarks; caller-pinned read view", Queries: []EvidenceProviderQuery{}, Fields: []EvidenceFieldSupply{}, Candidates: []domain.Event{}, Diagnostics: []string{}}
	r = &providerTraceReader{EvidenceReader: r, audit: &a}
	defer func() {
		a.ElapsedMS = time.Since(started).Milliseconds()
		c.Audit = a
		if err == nil {
			c, err = cloneEvidenceCollection(c)
			if err == nil {
				c.Seal()
			}
		}
	}()
	o, err := providerOptions(options)
	if err != nil {
		return c, err
	}
	a.ContractDigest = digest(o.Contracts)
	a.ProfileDigest = digest(o.Profile)
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	query := func(family, provider, method string, keys any, w evidence.AnalysisWindow, budget int) int {
		a.Queries = append(a.Queries, EvidenceProviderQuery{ID: "Q:" + family, Family: family, Rules: providerQueryRules(o.Contracts, family), Keys: keys, Window: w, Provider: provider, Method: method, Budget: budget, Status: "running"})
		return len(a.Queries) - 1
	}
	finish := func(i, n int, cov string, e error, t time.Time) {
		q := &a.Queries[i]
		q.Rows = n
		q.Coverage = cov
		q.Status = "completed"
		q.ElapsedMS = time.Since(t).Milliseconds()
		if e != nil {
			q.Status = "failed"
			q.Reason = e.Error()
		}
	}
	t := time.Now()
	qi := query("event", "EventDataProvider", "EvidenceEvent + AggregateRecord(segment/snapshot)", map[string]any{"event_id": id}, evidence.AnalysisWindow{}, 1)
	event, snap, err := (EventDataProvider{r}).Load(ctx, id)
	finish(qi, 1, "published_snapshot", err, t)
	if err != nil {
		return c, err
	}
	first, e1 := time.Parse(time.RFC3339Nano, asString(snap.Context["first_time"]))
	last, e2 := time.Parse(time.RFC3339Nano, asString(snap.Context["last_time"]))
	if e1 != nil || e2 != nil || last.Before(first) {
		return c, fmt.Errorf("snapshot_activity_window_missing")
	}
	w := evidence.AnalysisWindow{Start: first, End: last.Add(time.Nanosecond)}
	if !o.Start.IsZero() {
		w.Start = o.Start
	}
	if !o.End.IsZero() {
		w.End = o.End
	}
	if !w.Start.Before(w.End) || w.Start.Before(first) || w.End.After(last.Add(time.Nanosecond)) {
		return c, fmt.Errorf("requested_window_outside_published_snapshot")
	}
	t = time.Now()
	qi = query("asset", "AssetDataProvider", "EvidenceAssets", map[string]any{"bounded_registry": true}, w, o.MaxAssets)
	assets, err := (AssetDataProvider{r}).Load(ctx, o.MaxAssets)
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	finish(qi, len(assets), "registry_only", err, t)
	if err != nil {
		return c, err
	}
	t = time.Now()
	qi = query("traffic", "TrafficDataProvider", "SnapshotPage", map[string]any{"source_events": snap.Sources, "watermark": snap.Watermark, "revision_watermark": snap.RevisionWatermark}, w, o.MaxHits)
	hits, err := (TrafficDataProvider{r}).Load(ctx, snap, w, o)
	finish(qi, len(hits), "saved_hits_only_not_all_network", err, t)
	if err != nil {
		return c, err
	}
	fullWindow := w.Start.Equal(first) && w.End.Equal(last.Add(time.Nanosecond))
	if fullWindow && int64(len(hits)) != snap.Count {
		return c, fmt.Errorf("snapshot_membership_count_mismatch")
	}
	a.StoredHits = append(a.StoredHits, hits...)
	addresses, iocs, err := providerCollectionKeys(event, snap, assets, hits)
	if err != nil {
		return c, err
	}
	if len(iocs) > 32 || len(addresses) > 32 {
		return c, fmt.Errorf("provider_query_identity_budget_exceeded")
	}
	c = EvidenceCollection{SchemaVersion: EvidenceCollectionSchemaVersion, Event: event, Snapshot: snap, Assets: assets,
		Hits: collectEvidenceHits(hits), Window: w, Options: o, MatchAddresses: addresses, MatchIOCs: iocs,
		HistorySnapshots: map[string]CollectedSnapshotReference{}, Peers: []CollectedTrafficSnapshot{}}
	hw := evidence.AnalysisWindow{Start: w.Start.Add(-o.Lookback), End: w.Start}
	t = time.Now()
	qi = query("history", "HistoryDataProvider", "HistoryCandidates", map[string]any{"addresses": addresses, "iocs": iocs, "exclude": snap.Sources, "require_asset_ioc": true}, hw, o.MaxEvents)
	if len(addresses) > 0 && len(iocs) > 0 {
		cost := &providerSummaryCost{}
		c.HistoryCandidates, c.HistoryTruncated, err = providerCandidatesWithinBytes(ctx, r, store.HistoryQuery{Start: hw.Start, End: hw.End, Addresses: addresses, IOCs: iocs, ExcludeIDs: snap.Sources, RequireAssetIOC: true, SummaryOnly: true}, o.MaxEvents, 4<<20, cost)
		a.Queries[qi].Keys.(map[string]any)["summary_cost"] = cost
		finish(qi, len(c.HistoryCandidates), "event_history_only_not_contacts", err, t)
		if err != nil {
			return c, err
		}
	} else {
		finish(qi, 0, "unavailable", nil, t)
		a.Queries[qi].Reason = "asset_or_ioc_identity_unresolved"
	}
	if err = collectProviderRelatedHistory(ctx, r, &c, &a); err != nil {
		return c, err
	}
	t = time.Now()
	qi = query("group", "GroupDataProvider", "HistoryCandidates + SnapshotPage", map[string]any{"iocs": iocs, "exclude": snap.Sources}, w, o.MaxEvents)
	if len(iocs) > 0 {
		c.GroupCandidates, c.GroupTruncated, err = (GroupDataProvider{r}).Load(ctx, store.HistoryQuery{Start: w.Start, End: w.End, IOCs: iocs, ExcludeIDs: snap.Sources}, o.MaxEvents)
		finish(qi, len(c.GroupCandidates), "candidate_events_only", err, t)
		if err != nil {
			return c, err
		}
		a.Candidates = c.GroupCandidates
		if c.GroupTruncated {
			a.Diagnostics = append(a.Diagnostics, "group_candidate_budget_exceeded")
		}
		c.Peers, err = collectProviderPeers(ctx, r, c.GroupCandidates, w, o, &a)
		if err != nil {
			return c, err
		}
	} else {
		finish(qi, 0, "unavailable", nil, t)
		a.Queries[qi].Reason = "ioc_identity_unresolved"
	}
	t = time.Now()
	qi = query("context", "ContextDataProvider", "AggregateRecord(evidence_sources/active) + AggregateRecord(evidence_inputs/exact-snapshot)", map[string]any{"registry": "evidence_sources/active", "supplemental": "evidence_inputs/" + snapshotKey(snap.EventID, snap.Version)}, w, 2)
	record, exists, readErr := (ContextDataProvider{r}).Load(ctx)
	finish(qi, 0, "trusted_registry_only", readErr, t)
	if readErr != nil {
		a.Queries[qi].Reason = "source_registry_read_failed"
		return c, readErr
	}
	if exists {
		c.SourceRegistry = &record
	}
	supplementalRecord, supplementalExists, readErr := (ContextDataProvider{r}).LoadSupplemental(ctx, snap)
	if readErr != nil {
		a.Queries[qi].Status = "failed"
		a.Queries[qi].Reason = "supplemental_read_failed"
		return c, readErr
	}
	if supplementalExists {
		c.Supplemental = &supplementalRecord
	}
	return c, err
}

func collectProviderPeers(ctx context.Context, r store.EvidenceReader, peers []domain.Event, w evidence.AnalysisWindow, o EvidenceQueryOptions, a *EvidenceSupplyAudit) ([]CollectedTrafficSnapshot, error) {
	collected := []CollectedTrafficSnapshot{}
	remaining := o.MaxHits - len(a.StoredHits)
	remainingBytes := o.MaxBytes
	for _, h := range a.StoredHits {
		remainingBytes -= int64(len(h.Raw))
	}
	for _, e := range peers {
		started := time.Now()
		ledger := EvidenceProviderQuery{ID: "Q:peer:" + e.EventID, Family: "group", Rules: providerQueryRules(o.Contracts, "group"), Provider: "GroupDataProvider", Method: "EvidenceEvent + AggregateRecord(segment/snapshot) + SnapshotPage", Keys: map[string]any{"event_id": e.EventID}, Window: w, Budget: remaining, Status: "running", Coverage: "saved_hits_only"}
		_, s, err := (EventDataProvider{r}).Load(ctx, e.EventID)
		if err != nil {
			a.Diagnostics = append(a.Diagnostics, e.EventID+":published_snapshot_unavailable")
			ledger.Status = "unavailable"
			ledger.Reason = err.Error()
			ledger.ElapsedMS = time.Since(started).Milliseconds()
			a.Queries = append(a.Queries, ledger)
			if err.Error() != "published_segment_missing" && err.Error() != "published_snapshot_missing" && err.Error() != "event_not_found" {
				a.Queries[len(a.Queries)-1].Status = "failed"
				return nil, err
			}
			continue
		}
		if remaining <= 0 {
			return nil, fmt.Errorf("group_hit_budget_exceeded")
		}
		po := o
		po.MaxHits = remaining
		po.MaxBytes = remainingBytes
		hits, err := (TrafficDataProvider{r}).Load(ctx, s, w, po)
		if err != nil {
			ledger.Status = "failed"
			ledger.Reason = err.Error()
			a.Queries = append(a.Queries, ledger)
			return nil, err
		}
		ledger.Keys = map[string]any{"event_id": s.EventID, "source_events": s.Sources, "watermark": s.Watermark, "revision_watermark": s.RevisionWatermark}
		ledger.Rows = len(hits)
		ledger.Status = "completed"
		ledger.ElapsedMS = time.Since(started).Milliseconds()
		a.Queries = append(a.Queries, ledger)
		a.StoredHits = append(a.StoredHits, hits...)
		for _, h := range hits {
			remainingBytes -= int64(len(h.Raw))
		}
		remaining -= len(hits)
		collected = append(collected, CollectedTrafficSnapshot{Event: e, Snapshot: s, Hits: collectEvidenceHits(hits)})
	}
	return collected, nil
}
