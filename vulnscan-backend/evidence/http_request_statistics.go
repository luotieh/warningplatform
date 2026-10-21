package evidence

import "time"

func verifiedHTTPRequestStatistics(f Finding, g *observations, records []HTTPRecord, refs []string, start, end time.Time) Finding {
	f.SourceIDs = unique(refs)
	f.Measurements.Values = map[string]float64{}
	if len(records) == 0 {
		return absent(f, UnresolvedBinding)
	}
	f.Window = &Window{Start: start, End: end, Convention: "verified_request_subset_first_last_inclusive"}
	f.Dependencies = append(f.Dependencies, Dependency{Kind: "verified_http_request_statistics", Version: g.input.HTTP.Version + ":" + HTTPRequestVerificationVersion, SourceIDs: unique(refs)})
	if f.FactID == "F_HTTP_UA_RARITY" {
		f.ObservationKind = "complete_http_request_user_agent"
		uas := map[string]bool{}
		for _, r := range records {
			if r.UserAgent == "" {
				return absent(f, MissingInput)
			}
			uas[r.UserAgent] = true
		}
		f.Measurements.Values["distinct_user_agents"] = float64(len(uas))
		if len(uas) != 1 {
			f.Measurements.Values["consistent_ua"] = 0
			return finish(f, false, f.Measurements.Values, refs...)
		}
		f.Measurements.Values["consistent_ua"] = 1
		b, ok := baseline(&f, g, "ua_frequency", "ua_frequency_p01")
		if !ok {
			return absent(f, MissingBaseline)
		}
		if b[0] < 0 || b[0] > 1 || b[1] < 0 || b[1] > 1 {
			return absent(f, MissingBaseline)
		}
		f.Measurements.Values["ua_frequency"], f.Measurements.Values["ua_frequency_p01"] = b[0], b[1]
		return finish(f, b[0] < b[1], f.Measurements.Values, refs...)
	}
	f.ObservationKind = "complete_http_request_body_size"
	if len(records) < 12 {
		return absent(f, InsufficientSamples)
	}
	sizes := make([]float64, 0, len(records))
	distinct := map[uint64]bool{}
	for _, r := range records {
		sizes = append(sizes, float64(*r.BodyLength))
		distinct[*r.BodyLength] = true
	}
	avg, cv := moments(sizes)
	ratio := float64(len(distinct)) / float64(len(records))
	f.Measurements.Values["request_body_mean"] = avg
	f.Measurements.Values["size_cv"] = cv
	f.Measurements.Values["unique_size_ratio"] = ratio
	b, ok := baseline(&f, g, "size_cv_p05", "unique_size_ratio_p05")
	if !ok {
		return absent(f, MissingBaseline)
	}
	if b[0] < 0 || b[1] < 0 || b[1] > 1 {
		return absent(f, MissingBaseline)
	}
	return finish(f, avg > 0 && cv < b[0] && ratio < b[1], f.Measurements.Values, refs...)
}
