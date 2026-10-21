package evidence

// A verified prior occurrence refutes platform-first-seen even when history
// retrieval is partial. The converse is deliberately unavailable on this path.
// Identity is the typed IOC, not the historical asset, sensor, or endpoint.
func verifiedPriorIOCOccurrence(subject HistorySubject, g *observations) Finding {
	f := baseFinding("F_IOC_NOVELTY", g, Parameters{}, []string{
		"仅以已核验的同类型、同值IOC历史事件反证平台首现；历史事件数是已检索下界，不是完整历史总数",
		"不要求历史资产或采集设备与当前相同；不证明恶意、首次真实连接或当前行为性质",
		"未找到历史事件仍为缺失，不据部分历史声明首现",
	})
	f.ObservationKind = "verified_prior_ioc_occurrence"
	f.Quality = "verified_prior_occurrence_subset"
	f.FeatureClaim = "Verified earlier platform events refute first-seen status for the same typed IOC"
	f.CannotProve = "Does not prove complete history, an exact prior event count, maliciousness, or first real contact; no match cannot establish novelty"
	f.Measurements.SampleCount = 0
	f.Measurements.Values = map[string]float64{"prior_matches_lower_bound": 0}
	if g.input == nil || g.request == nil || subject.History == nil {
		return absent(f, MissingInput)
	}
	// Reuse the typed current-source contract even when called independently of
	// Engine.Evaluate. Only the selected subject's bound current hits are local.
	in := *g.input
	in.PlatformHistorySubjects = []HistorySubject{subject}
	hits := map[string]Hit{}
	for _, hit := range g.hits {
		hits[hit.ID] = hit
	}
	if err := ValidateHistorySubjects(&in, hits); err != nil {
		return absent(f, UnresolvedBinding)
	}
	h := subject.History
	if !h.PlatformRecords || !validHistory(h, g.request.EventID) {
		return absent(f, MissingInput)
	}
	if len(g.hits) == 0 {
		return absent(f, UnresolvedBinding)
	}
	earliest := g.hits[0].OccurredAt
	for _, hit := range g.hits[1:] {
		if hit.OccurredAt.Before(earliest) {
			earliest = hit.OccurredAt
		}
	}
	if h.AsOf.After(earliest) {
		return absent(f, UnresolvedBinding)
	}
	provenSources := map[string]bool{}
	for _, id := range h.SourceIDs {
		provenSources[id] = true
	}
	refs := append([]string(nil), g.sourceIDs...)
	for _, event := range h.Events {
		// validHistory already rejects current-event IDs, duplicate IDs, and
		// dates outside [LookbackStart, AsOf). Keep zero-time explicit here.
		if event.Time.IsZero() {
			return absent(f, InvalidTime)
		}
		if !provenSources[event.ID] {
			return absent(f, UnresolvedBinding)
		}
		refs = append(refs, event.ID)
	}
	f.Measurements.SampleCount = len(h.Events)
	f.Measurements.Values["prior_matches_lower_bound"] = float64(len(h.Events))
	f.Window = &Window{Start: h.LookbackStart, End: h.AsOf, Convention: "verified_history_subset_half_open"}
	dependency(&f, "verified_prior_ioc_occurrence", h.Provenance)
	if len(h.Events) == 0 {
		return absent(f, UnverifiedCoverage)
	}
	// Never produce Observed here, even if the caller marks history complete.
	return finish(f, false, f.Measurements.Values, refs...)
}
