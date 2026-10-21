package evidence

func verifiedPriorEndpointOccurrence(f Finding, g *observations) Finding {
	f.ObservationKind = "verified_prior_asset_endpoint_occurrence"
	f.Quality = "verified_prior_occurrence_subset"
	f.FeatureClaim = "Saved earlier alerts for the same asset, sensor and transport endpoint refute endpoint first-seen status"
	f.CannotProve = "Does not prove complete history, successful connections, maliciousness or first real contact; no match cannot establish novelty"
	f.Limitations = append(f.Limitations, "仅反证同资产、同设备、同协议/IP/端口的历史告警首现；不证明实际连接成功；零匹配仍为缺失")
	f.SourceIDs = nil
	target := canonicalEndpoint(g.scope.EndpointID)
	if target == "" || g.input.Window == nil || len(g.hits) == 0 {
		return absent(f, UnresolvedBinding)
	}
	hits := map[string]Hit{}
	for _, h := range g.hits {
		hits[h.ID] = h
	}
	if ValidateHistorySubjects(g.input, hits) != nil {
		return absent(f, UnresolvedBinding)
	}
	refs := append([]string(nil), g.sourceIDs...)
	seen := map[string]bool{}
	for _, subject := range g.input.PlatformHistorySubjects {
		h := subject.History
		if !h.PlatformRecords || !validHistory(h, g.request.EventID) || h.AsOf.After(g.input.Window.Start) {
			return absent(f, UnresolvedBinding)
		}
		if f.Window == nil || f.Window.Convention != "verified_history_subset_half_open" {
			f.Window = &Window{Start: h.LookbackStart, End: h.AsOf, Convention: "verified_history_subset_half_open"}
		} else {
			if h.LookbackStart.Before(f.Window.Start) {
				f.Window.Start = h.LookbackStart
			}
			if h.AsOf.After(f.Window.End) {
				f.Window.End = h.AsOf
			}
		}
		sources := map[string]bool{}
		for _, id := range h.SourceIDs {
			sources[id] = true
		}
		for _, r := range h.Events {
			if r.Time.IsZero() || !sources[r.ID] {
				return absent(f, UnresolvedBinding)
			}
			if r.AssetID != g.scope.AssetID || r.DeviceID != g.scope.DeviceID || canonicalEndpoint(r.Endpoint) != target {
				continue
			}
			if !seen[r.ID] {
				seen[r.ID] = true
				refs = append(refs, r.ID)
			}
		}
		dependency(&f, "saved_asset_endpoint_history", h.Provenance)
	}
	f.Measurements.SampleCount = len(seen)
	f.Measurements.Values = map[string]float64{"prior_matches_lower_bound": float64(len(seen))}
	if len(seen) == 0 {
		return absent(f, UnverifiedCoverage)
	}
	return finish(f, false, f.Measurements.Values, unique(refs)...)
}
