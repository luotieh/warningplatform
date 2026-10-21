package service

import (
	"context"
	"sort"
	"time"

	"vulnscan-backend/evidence"
)

const temporalInputScopeVersion = "event-time-scope-1"

// Never backfill a short current-event communication sequence with history or
// group peers. An event can include multiple original source IDs, but its
// contacts all carry the identity of the current frozen snapshot.
func phaseOneCurrentContacts(snap EvidenceSnapshot, m PhaseOneMaterials) []PhaseOneContact {
	contacts := m.Contacts
	if m.Expanded && len(m.CurrentContacts) > 0 {
		contacts = m.CurrentContacts
	}
	out := []PhaseOneContact{}
	for _, c := range contacts {
		if c.Snapshot.EventID == snap.EventID {
			out = append(out, c)
		}
	}
	return out
}

// Fixed-daily scheduling and historical persistence operate on event starts,
// one sample per EventID. Neither event duration nor the number of packet hits
// multiplies a historical event or fills the dates between its first/last time.
func phaseOneEventTimeFacts(ctx context.Context, snap EvidenceSnapshot, m PhaseOneMaterials, h ReportHistory, facts []evidence.FactID) ([]evidence.Finding, error) {
	bindings := map[string]evidence.PhaseOneBinding{}
	currentBindings := m.Bindings
	if m.CurrentBindings != nil {
		currentBindings = m.CurrentBindings
	}
	for _, b := range currentBindings {
		if b.Verified {
			bindings[scopeKey(b.Scope)+b.IOCType+":"+b.IOCValue] = b
		}
	}
	keys := []string{}
	for key := range bindings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	first, parseErr := time.Parse(time.RFC3339Nano, asString(snap.Context["first_time"]))
	if asString(snap.Context["first_time"]) == "" {
		// Older prepared inputs may omit context first_time, while retaining
		// the actual current-event observation timestamps.
		for _, c := range phaseOneCurrentContacts(snap, m) {
			if first.IsZero() || c.Time.Before(first) {
				first = c.Time
			}
		}
		parseErr = nil
	}
	engine, err := evidence.NewEngine(evidence.DefaultConfig())
	if err != nil {
		return nil, err
	}
	out := []evidence.Finding{}
	for _, key := range keys {
		b := bindings[key]
		complete := h.Status == "available" && !h.Truncated && h.ExcludedCount == 0
		if h.EventSummaryOnly {
			complete = h.EventSummaryComplete
		}
		req := evidence.Request{EventID: snap.EventID, SnapshotVersion: snap.Version, Facts: facts, Quality: evidence.Quality{Coverage: evidence.CoverageComplete}}
		seen := map[string]bool{snap.EventID: true}
		for _, source := range snap.Sources {
			seen[source] = true
		}
		if parseErr == nil && !first.IsZero() {
			req.Hits = append(req.Hits, evidence.Hit{ID: snap.EventID, OccurredAt: first, Scope: b.Scope})
		}
		for _, row := range h.Rows {
			if seen[row.EventID] || row.EventID == "" || row.DeviceID != b.Scope.DeviceID || len(row.AllAssetIDs) != 1 || row.AllAssetIDs[0] != b.Scope.AssetID {
				continue
			}
			match := false
			for _, ioc := range row.IOCs {
				match = match || ioc.Type == b.IOCType && ioc.Value == b.IOCValue
			}
			if !match {
				continue
			}
			if row.First.IsZero() || row.Last.Before(row.First) || row.First.Before(h.Start) || !row.Last.Before(h.End) {
				complete = false
				continue
			}
			seen[row.EventID] = true
			req.Hits = append(req.Hits, evidence.Hit{ID: row.EventID, OccurredAt: row.First, Scope: b.Scope})
		}
		if !complete {
			req.Quality.Coverage = evidence.CoveragePartial
		}
		req.Quality.SavedTimelineComplete = &complete
		no := false
		req.Quality.CaptureTruncated = &no // event summary input, not packet capture input
		if parseErr != nil || first.IsZero() {
			for _, id := range facts {
				out = append(out, evidence.Finding{FactID: id, Scope: b.Scope, IOCType: b.IOCType, IOCValue: b.IOCValue, ObservationKind: "event_occurrence", SnapshotVersion: snap.Version, RuleVersion: evidence.RuleVersion, Status: evidence.Missing, Eligibility: "ineligible", Quality: "partial", ReasonCode: evidence.InvalidTime})
			}
			continue
		}
		result, err := engine.Evaluate(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, f := range result.Findings {
			f.IOCType, f.IOCValue, f.ObservationKind = b.IOCType, b.IOCValue, "event_occurrence"
			f.Limitations = append(f.Limitations, "event-level occurrence times; one sample per event; not a connection/request frequency or network capture claim")
			out = append(out, f)
		}
	}
	return out, nil
}
