package service

import (
	"fmt"
	"sort"
	"time"

	"vulnscan-backend/evidence"
)

// Background grouping of observed assets, not proof of cooperation or membership
// in an externally registered campaign. Batches retain all assets and sources.
func addReportObservedGroupSubjects(r *evidence.SemanticRequest, input SnapshotEvidenceInput, factory semanticMaterialFactory) {
	bound := map[string]evidence.Hit{}
	for _, h := range input.Request.Hits {
		bound[h.ID] = h
	}
	groups := map[string][]ReportMaterialObservation{}
	for _, o := range input.Manifest.ReportObservations {
		if hit, ok := bound[o.HitID]; !ok || hit.Scope != o.Scope || !hit.OccurredAt.Equal(o.Time) || o.Time.IsZero() {
			continue
		}
		key := o.Scope.EndpointID + " / " + o.Time.In(reportDayLocation).Format("2006-01-02")
		groups[key] = append(groups[key], o)
	}
	keys := []string{}
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		members := map[string][]ReportMaterialObservation{}
		var first, last time.Time
		for _, o := range groups[key] {
			members[o.Scope.AssetID] = append(members[o.Scope.AssetID], o)
			if first.IsZero() || o.Time.Before(first) {
				first = o.Time
			}
			if last.IsZero() || o.Time.After(last) {
				last = o.Time
			}
		}
		assets := []string{}
		for asset := range members {
			if asset != "" {
				assets = append(assets, asset)
			}
		}
		sort.Strings(assets)
		if len(assets) < 2 {
			continue
		}
		groupID := "report-observed:" + digest(key)
		batches := (len(assets) + 4) / 5
		offset := 0
		for part := 0; part < batches; part++ {
			count := (len(assets) - offset + batches - part - 1) / (batches - part)
			s := evidence.SemanticSubject{ID: fmt.Sprintf("observed-group:%s:%d", groupID, part), PropositionID: groupID, Scope: evidence.Scope{GroupID: groupID}, Window: evidence.AnalysisWindow{Start: first.UTC(), End: last.Add(time.Nanosecond).UTC()}}
			for _, asset := range assets[offset : offset+count] {
				refs := []string{}
				for _, o := range members[asset] {
					refs = append(refs, o.HitID)
				}
				sort.Strings(refs)
				refs = compactReportRefs(refs)
				p := evidence.Provenance{Verified: true, Complete: true, Version: fmt.Sprintf("report-observed-group:%d", r.SnapshotVersion), SourceIDs: refs}
				m := factory(&s, "group_member", fmt.Sprintf("资产=%s；同日共同端点=%s；保存命中%d条；这是观测分组，不证明协同、同战役或资产角色", asset, key, len(refs)), "snapshot.observed_asset_group", p, true)
				m.ID += ":" + asset
				m.AssetID = asset
				s.Materials = append(s.Materials, m)
			}
			r.Subjects = append(r.Subjects, s)
			offset += count
		}
	}
}
