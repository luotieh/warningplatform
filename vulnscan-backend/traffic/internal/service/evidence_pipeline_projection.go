package service

import (
	"encoding/json"
	"sort"
	"vulnscan-backend/evidence"
)

// Whole evidence/detail instances only: omitted measurements remain in the
// audit, never silently truncated into an apparently complete statistic.
func boundedPipelineEssence(b ReportEvidenceBundle) ReportEssenceBundle {
	e := reportEssenceFor(b)
	details := map[string]ReportEssenceDetail{}
	for _, d := range e.Details {
		details[d.ID] = d
	}
	entries := map[string]ReportEvidence{}
	for _, x := range b.Entries {
		entries[x.ID] = x
	}
	items := append([]ReportEssence(nil), e.Items...)
	priority := func(x ReportEssence) int {
		v := entries[x.ID]
		if v.Semantic != nil && v.Semantic.Judgement == "support" && !v.Semantic.ExplanationOnly {
			return 0
		}
		if v.FactID == "F_FIXED_DAILY_WINDOW" || v.FactID == "F_HIST_ASSET_IOC_RECURRENCE" {
			return 1
		}
		if v.Finding != nil && v.Status == "observed" {
			return 2
		}
		if v.Kind == "intelligence" {
			return 3
		}
		return 4
	}
	sort.SliceStable(items, func(i, j int) bool { return priority(items[i]) < priority(items[j]) })
	out := e
	out.Items = nil
	out.Details = nil
	used, names := map[string]bool{}, map[string]bool{}
	kept := map[string]bool{}
	budget := 0
	for _, x := range items {
		if names[x.Name] {
			continue
		}
		ds := []ReportEssenceDetail{}
		for _, id := range x.Details {
			if d, ok := details[id]; ok && !used[id] {
				ds = append(ds, d)
			}
		}
		raw, _ := json.Marshal([]any{x, ds})
		if len(out.Items) >= 12 || budget+len(raw) > 12000 {
			continue
		}
		budget += len(raw)
		out.Items = append(out.Items, x)
		names[x.Name] = true
		kept[x.ID] = true
		for _, d := range ds {
			out.Details = append(out.Details, d)
			used[d.ID] = true
		}
	}
	out.Trace = append([]ReportEssenceTrace(nil), e.Trace...)
	for i := range out.Trace {
		t := &out.Trace[i]
		if t.EvidenceID != "" && !kept[t.EvidenceID] {
			t.EvidenceID = ""
			t.DetailID = ""
			t.Reason = "pipeline_projection_budget_or_repeated_name"
		}
	}
	out.ProjectionOmitted = len(e.Items) - len(out.Items)
	out.ProjectionByteBudget = 12000
	return out
}
func pipelineOverviewProjection(o ReportEventOverview) map[string]any {
	tuples := o.Tuples[:min(4, len(o.Tuples))]
	iocs := append([]ReportOverviewIOC(nil), o.IOCs[:min(4, len(o.IOCs))]...)
	for i := range iocs {
		iocs[i].Activity = truncateRunes(iocs[i].Activity, 200)
		iocs[i].Source = truncateRunes(iocs[i].Source, 100)
		iocs[i].Category = truncateRunes(iocs[i].Category, 100)
	}
	return map[string]any{"first": o.First, "last": o.Last, "saved_hits": o.SavedHits, "bound_hits": o.BoundHits, "physical_packets": o.PhysicalPackets, "packet_bytes": o.PacketBytes, "sized_packets": o.SizedPackets, "plaintext": o.Plaintext, "five_tuples": tuples, "iocs": iocs, "omitted_five_tuples": len(o.Tuples) - len(tuples), "omitted_iocs": len(o.IOCs) - len(iocs), "coverage_note": "bounded context projection; omitted instances remain in pipeline audit; hit counts are not communication counts"}
}
func pipelineJointUnitProjection(u evidence.PhaseOneUnit) map[string]any {
	out := map[string]any{"id": u.ID, "scope": u.Scope, "status": u.Status, "score": u.Score, "reason": u.Reason, "duplicate_of": u.DuplicateOf}
	if u.Fact != nil {
		raw, _ := json.Marshal(u.Fact.Measurements)
		if len(raw) <= 1800 {
			out["measurements"] = u.Fact.Measurements
		} else {
			out["measurements_omitted"] = "audit_only_budget"
		}
	}
	return out
}
