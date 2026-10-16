package service

import (
	"context"
	"sort"
	"vulnscan-backend/evidence"
)

func pipelineBaseFacts(selected []evidence.FactID) []evidence.FactID {
	deferred := map[evidence.FactID]bool{evidence.BeaconPeriodic: true, evidence.MultiDayPersist: true}
	for _, id := range evidence.PhaseOneFacts() {
		deferred[id] = true
	}
	base := []evidence.FactID{}
	for _, id := range selected {
		if !deferred[id] {
			base = append(base, id)
		}
	}
	return base
}

func pipelinePendingFacts(result *evidence.Result, original evidence.Request) {
	base := map[evidence.FactID]bool{}
	for _, id := range pipelineBaseFacts(original.Facts) {
		base[id] = true
	}
	// The base engine records unrequested rules too. Replace those placeholders
	// before adding independently supplied executions for the same rule/scope.
	kept := result.Executions[:0]
	for _, x := range result.Executions {
		deferred := false
		for _, id := range original.Facts {
			if id == x.FactID && !base[id] {
				deferred = true
				break
			}
		}
		if !deferred {
			kept = append(kept, x)
		}
	}
	result.Executions = kept
	scopes := map[evidence.Scope][]string{}
	for _, hit := range original.Hits {
		scopes[hit.Scope] = append(scopes[hit.Scope], hit.ID)
	}
	ordered := []evidence.Scope{}
	for scope := range scopes {
		ordered = append(ordered, scope)
	}
	sort.Slice(ordered, func(i, j int) bool { return scopeKey(ordered[i]) < scopeKey(ordered[j]) })
	for _, d := range evidence.Definitions() {
		requested := false
		for _, id := range original.Facts {
			if id == d.ID {
				requested = true
			}
		}
		if !requested || base[d.ID] {
			continue
		}
		for _, scope := range ordered {
			result.Findings = append(result.Findings, evidence.Finding{EvidenceContract: d.EvidenceContract, FactID: d.ID, RuleVersion: evidence.RuleVersion, SnapshotVersion: original.SnapshotVersion, Scope: scope, Status: evidence.Missing, Eligibility: "ineligible", Quality: "partial", ReasonCode: evidence.MissingInput, SourceIDs: scopes[scope], Limitations: []string{"independent observation or protocol supply unavailable"}})
			result.Executions = append(result.Executions, evidence.Execution{FactID: d.ID, Scope: scope, Status: "skipped", ReasonCode: evidence.MissingInput})
		}
	}
}

// General temporal facts share phase-one's independently deduplicated contact
// supply. Byte/packet counts remain unknown unless measured per communication.
func pipelineIndependentTemporalFacts(ctx context.Context, snap EvidenceSnapshot, m PhaseOneMaterials) ([]evidence.Finding, error) {
	groups := map[string][]PhaseOneContact{}
	for _, c := range m.Contacts {
		k := scopeKey(c.Scope) + c.IOCType + ":" + c.IOCValue + "|" + c.Kind
		groups[k] = append(groups[k], c)
	}
	keys := []string{}
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	engine, err := evidence.NewEngine(evidence.DefaultConfig())
	if err != nil {
		return nil, err
	}
	findings := []evidence.Finding{}
	for _, key := range keys {
		contacts := groups[key]
		coverageKey := scopeKey(contacts[0].Scope) + contacts[0].IOCType + ":" + contacts[0].IOCValue
		complete, truncated := m.Complete && len(m.ScopeIncomplete[coverageKey]) == 0, false
		r := evidence.Request{EventID: snap.EventID, SnapshotVersion: snap.Version, Facts: []evidence.FactID{evidence.BeaconPeriodic, evidence.MultiDayPersist}, Quality: evidence.Quality{Coverage: evidence.CoveragePartial, SavedTimelineComplete: &complete, CaptureTruncated: &truncated}}
		if complete {
			r.Quality.Coverage = evidence.CoverageComplete
		}
		seen := map[string]bool{}
		for _, c := range contacts {
			if !seen[c.HitID] {
				r.Hits = append(r.Hits, evidence.Hit{ID: c.HitID, OccurredAt: c.Time, Scope: c.Scope})
				seen[c.HitID] = true
			}
		}
		result, e := engine.Evaluate(ctx, r)
		if e != nil {
			return nil, e
		}
		for _, f := range result.Findings {
			f.IOCType, f.IOCValue = contacts[0].IOCType, contacts[0].IOCValue
			f.ObservationKind = contacts[0].Kind
			findings = append(findings, f)
		}
	}
	return findings, nil
}
