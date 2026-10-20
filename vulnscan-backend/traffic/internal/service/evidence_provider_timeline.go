package service

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

// Historical alerts only select snapshots. Contacts come exclusively from
// their frozen, validated wire records and must match a current scope and IOC.
// No database access, event timestamp substitution or coverage upgrade occurs.
func preprocessProviderTimeline(ctx context.Context, c EvidenceCollection, out *SnapshotEvidenceInput, history *ReportHistory, audit *EvidenceSupplyAudit) error {
	m := out.Manifest.PhaseOne
	allowed := map[string]bool{}
	allowedTimeline := map[string]bool{}
	for _, b := range m.Bindings {
		if b.Verified {
			allowed[providerContactKey(b.Scope, b.IOCType, b.IOCValue)] = true
			allowedTimeline[scopeKey(b.Scope)+b.IOCType+":"+b.IOCValue] = true
		}
	}
	accepted := map[string]bool{}
	for _, row := range history.Rows {
		accepted[row.EventID] = true
	}
	for _, candidate := range c.HistoryCandidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		ref := c.HistorySnapshots[candidate.EventID]
		if !ref.Loaded || ref.Reason != "" {
			m.Diagnostics = append(m.Diagnostics, candidate.EventID+":historical_contacts_unavailable:"+ref.Reason)
			continue
		}
		if ref.EventID != candidate.EventID || ref.Snapshot.EventID != candidate.EventID || int64(len(ref.Hits)) != ref.Snapshot.Count {
			return fmt.Errorf("collected_history_snapshot_binding_mismatch:%s", candidate.EventID)
		}
		start, e1 := time.Parse(time.RFC3339Nano, asString(ref.Snapshot.Context["first_time"]))
		end, e2 := time.Parse(time.RFC3339Nano, asString(ref.Snapshot.Context["last_time"]))
		if e1 != nil || e2 != nil || end.Before(start) || start.Before(history.Start) || !end.Before(history.End) {
			return fmt.Errorf("collected_history_window_mismatch:%s", candidate.EventID)
		}
		input, _, _, err := assembleProviderTraffic(ref.Snapshot, c.Assets, collectedStoreHits(ref.Hits), evidence.AnalysisWindow{Start: start, End: end.Add(time.Nanosecond)})
		if err != nil {
			return err
		}
		for key, reasons := range input.Manifest.PhaseOne.ScopeIncomplete {
			if !allowedTimeline[key] {
				continue
			}
			if m.ScopeIncomplete == nil {
				m.ScopeIncomplete = map[string][]string{}
			}
			m.ScopeIncomplete[key] = append(m.ScopeIncomplete[key], reasons...)
		}
		contacts := []PhaseOneContact{}
		for _, contact := range input.Manifest.PhaseOne.Contacts {
			if contact.Time.Before(history.Start) || !contact.Time.Before(history.End) || !allowed[providerContactKey(contact.Scope, contact.IOCType, contact.IOCValue)] {
				continue
			}
			contacts = append(contacts, contact)
		}
		if len(contacts) == 0 {
			m.Diagnostics = append(m.Diagnostics, candidate.EventID+":no_verified_same_scope_ioc_contacts")
			continue
		}
		m.Contacts = append(m.Contacts, contacts...)
		m.Sources = append(m.Sources, input.Manifest.PhaseOne.Sources...)
		m.Diagnostics = append(m.Diagnostics, input.Manifest.PhaseOne.Diagnostics...)
		// Repair a metadata join only when the frozen wire independently proves
		// one asset/device relation. Mixed scopes still supply separate contacts.
		scope := contacts[0].Scope
		oneScope := true
		for _, contact := range contacts {
			oneScope = oneScope && contact.Scope == scope
		}
		if !accepted[candidate.EventID] && oneScope {
			first, last := contacts[0].Time, contacts[0].Time
			iocs := []domain.IOC{}
			seen := map[string]bool{}
			for _, contact := range contacts {
				if contact.Time.Before(first) {
					first = contact.Time
				}
				if contact.Time.After(last) {
					last = contact.Time
				}
				key := contact.IOCType + ":" + contact.IOCValue
				if !seen[key] {
					seen[key] = true
					iocs = append(iocs, domain.IOC{Type: contact.IOCType, Value: contact.IOCValue})
				}
			}
			address := ""
			for _, asset := range c.Assets {
				if asset.ID == scope.AssetID {
					address = asset.Address
				}
			}
			endpoint, _ := url.Parse(scope.EndpointID)
			remote := ""
			if endpoint != nil {
				remote = endpoint.Hostname()
			}
			history.Rows = append(history.Rows, ReportHistoryRow{EventID: candidate.EventID, DeviceID: scope.DeviceID, First: first, Last: last, AssetIDs: []string{scope.AssetID}, AllAssetIDs: []string{scope.AssetID}, IOCs: iocs, ActivityIOCs: iocs, SourceAddress: address, DestinationAddress: remote, Relation: "same_asset_ioc", Adjudication: "unreviewed"})
			accepted[candidate.EventID] = true
			if history.ExcludedCount > 0 {
				history.ExcludedCount--
			}
			for i := range audit.HistoryChecks {
				check := &audit.HistoryChecks[i]
				if check.EventID != candidate.EventID {
					continue
				}
				check.Accepted, check.DeviceMatch, check.AssetMatch, check.IOCMatch, check.EndpointMatch = true, true, true, true, true
				check.First, check.Stage, check.Reasons = first, "", []string{}
				check.SourceQuality = "frozen wire contacts bound to current asset/device/endpoint/IOC; communication coverage remains partial"
			}
		}
	}
	sort.Slice(history.Rows, func(i, j int) bool {
		if history.Rows[i].First.Equal(history.Rows[j].First) {
			return history.Rows[i].EventID < history.Rows[j].EventID
		}
		return history.Rows[i].First.Before(history.Rows[j].First)
	})
	*m = dedupPhaseOneContacts(*m)
	// Saved row-count equality proves snapshot membership only. The separate
	// temporal-window policy can assume coverage without changing these proofs.
	m.Complete, m.CurrentComplete = false, false
	complete := false
	out.Request.Quality.SavedTimelineComplete = &complete
	return nil
}

// Peer snapshots can carry the SYN and first HTTP request in separate events.
// Reconcile both timelines after merging, without bringing history into current.
func dedupProviderContactSets(out *SnapshotEvidenceInput) {
	m := out.Manifest.PhaseOne
	current := dedupPhaseOneContacts(PhaseOneMaterials{Contacts: m.CurrentContacts, ScopeIncomplete: m.CurrentIncomplete})
	*m = dedupPhaseOneContacts(*m)
	m.CurrentContacts, m.CurrentIncomplete = current.Contacts, current.ScopeIncomplete
}

func applyProviderTemporalWindowDefault(c EvidenceCollection, out *SnapshotEvidenceInput) {
	m := out.Manifest.PhaseOne
	currentComplete := out.Manifest.LoadedHits == out.Manifest.DeclaredHits && out.Manifest.UnresolvedHits == 0
	for _, source := range m.Sources {
		// Historical sources were also fully read; their absence is checked below.
		currentComplete = currentComplete && source.Complete
	}
	complete := currentComplete && !c.HistoryTruncated
	for _, candidate := range c.HistoryCandidates {
		ref, ok := c.HistorySnapshots[candidate.EventID]
		if !ok || !ref.Loaded || ref.Reason != "" || int64(len(ref.Hits)) != ref.Snapshot.Count {
			complete = false
		}
	}
	m.TemporalWindowCoverage = &PhaseOneTemporalWindowCoverage{Basis: assumedTemporalWindowCoverage, CurrentComplete: currentComplete, Complete: complete}
	m.Diagnostics = append(m.Diagnostics, "temporal_window_coverage:default_assumption; applies only to F_BEACON_JITTER and F_FIXED_DAILY_WINDOW; known read gaps and scope incompleteness still apply")
}

func providerContactKey(scope evidence.Scope, kind, value string) string {
	return scopeKey(scope) + "|" + kind + "|" + value
}
