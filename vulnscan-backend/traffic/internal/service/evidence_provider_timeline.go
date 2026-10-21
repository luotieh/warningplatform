package service

import (
	"context"
)

// Event history supplies event-level occurrence times, never communication
// samples. Old saved collections may contain historical packets; deliberately
// ignore those packets so replay follows the same boundary as new collection.
func preprocessProviderTimeline(ctx context.Context, c EvidenceCollection, out *SnapshotEvidenceInput, history *ReportHistory, audit *EvidenceSupplyAudit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m := out.Manifest.PhaseOne
	m.Diagnostics = append(m.Diagnostics, "temporal_scope:current_event_contacts_only; historical_event_times_are_separate")
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
	complete := currentComplete

	m.TemporalWindowCoverage = &PhaseOneTemporalWindowCoverage{Basis: assumedTemporalWindowCoverage, CurrentComplete: currentComplete, Complete: complete}
	m.Diagnostics = append(m.Diagnostics, "temporal_window_coverage:default_assumption; applies only to F_BEACON_JITTER; current-event read gaps and scope incompleteness still apply; historical packets are not consumed")
}
