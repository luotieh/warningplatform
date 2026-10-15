package service

import (
	"context"
	"sort"
	"time"
	"vulnscan-backend/evidence"
)

func phaseOneCurrentFacts(ctx context.Context, snap EvidenceSnapshot, m PhaseOneMaterials, h ReportHistory) ([]evidence.Finding, error) {
	groups := map[string][]evidence.PhaseOneBinding{}
	for _, b := range m.Bindings {
		if b.Verified {
			k := scopeKey(b.Scope) + b.IOCType + ":" + b.IOCValue
			groups[k] = append(groups[k], b)
		}
	}
	findings := []evidence.Finding{}
	engine, _ := evidence.NewEngine(evidence.DefaultConfig())
	keys := []string{}
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		bindings := groups[key]
		b := bindings[0]
		ids := map[string]bool{}
		for _, b := range bindings {
			ids[b.SourceID] = true
		}
		req := evidence.Request{EventID: snap.EventID, SnapshotVersion: snap.Version, Facts: []evidence.FactID{"F_HIST_ASSET_IOC_RECURRENCE", "F_HTTP_ENDPOINT_REPEAT"}, Quality: evidence.Quality{Coverage: evidence.CoverageComplete}}
		notTruncated := false
		req.Quality.CaptureTruncated = &notTruncated
		input := evidence.Input{Scope: b.Scope}
		http := evidence.HTTPData{Provenance: evidence.Provenance{Verified: true, Complete: true, Version: evidence.PhaseOneVersion}}
		seen := map[string]bool{}
		var start, end time.Time
		for _, r := range m.Records {
			if !ids[r.Hit.ID] {
				continue
			}
			req.Hits = append(req.Hits, r.Hit)
			if start.IsZero() || r.Hit.OccurredAt.Before(start) {
				start = r.Hit.OccurredAt
			}
			if end.IsZero() || r.Hit.OccurredAt.After(end) {
				end = r.Hit.OccurredAt
			}
			if r.HTTPCandidate {
				http.RequestCandidates++
				if r.HTTP == nil || r.HTTP.Truncated || r.RawRequest == "" {
					http.Complete = false
				}
				if r.HTTP != nil && !seen[r.HTTP.RequestID] {
					seen[r.HTTP.RequestID] = true
					http.Records = append(http.Records, *r.HTTP)
					http.SourceIDs = append(http.SourceIDs, r.Hit.ID)
				}
			}
		}
		if len(req.Hits) == 0 {
			continue
		}
		input.Window = &evidence.AnalysisWindow{Start: start, End: end.Add(time.Nanosecond)}
		if len(http.Records) > 0 {
			input.HTTP = &http
		}
		hist := &evidence.HistoryData{Provenance: evidence.Provenance{Verified: true, Complete: h.Status == "available" && !h.Truncated && h.ExcludedCount == 0, Version: h.Version + ":" + digest(h)}, PlatformRecords: true, AsOf: h.End, LookbackStart: h.Start, IOC: b.IOCValue, Endpoint: b.Scope.EndpointID}
		for _, row := range h.Rows {
			if row.DeviceID != b.Scope.DeviceID || !phaseOneContains(row.AllAssetIDs, b.Scope.AssetID) || !row.Last.Before(h.End) {
				continue
			}
			target := false
			for _, ioc := range row.IOCs {
				if ioc.Type == b.IOCType && ioc.Value == b.IOCValue {
					target = true
				}
			}
			if !target {
				continue
			}
			kind := "application_contact"
			if b.IOCType == "ip" {
				if row.SourceAddress != b.IOCValue && row.DestinationAddress != b.IOCValue {
					continue
				}
				kind = "transport_contact"
			}
			hist.Events = append(hist.Events, evidence.HistoryEvent{ID: row.EventID, AssetID: b.Scope.AssetID, AssetIDs: row.AllAssetIDs, IOC: b.IOCValue, Time: row.First, Relation: "same_asset_ioc", ObservationKind: kind})
			hist.SourceIDs = append(hist.SourceIDs, row.EventID)
		}
		input.PlatformHistory = hist
		input.History = hist
		req.Inputs = []evidence.Input{input}
		computed, err := engine.Evaluate(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, f := range computed.Findings {
			f.IOCType, f.IOCValue = b.IOCType, b.IOCValue
			findings = append(findings, f)
		}
	}
	// DNS hard facts are per real question, so a positive encoded label cannot
	// authorize another question's semantic interpretation at the same resolver.
	for _, r := range m.Records {
		if r.DNS == nil {
			continue
		}
		f, err := phaseOneDNSFact(ctx, snap, r)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f...)
	}
	return findings, nil
}
func phaseOneContains(values []string, want string) bool {
	for _, s := range values {
		if s == want {
			return true
		}
	}
	return false
}
func phaseOneDNSFact(ctx context.Context, snap EvidenceSnapshot, r PhaseOneRecord) ([]evidence.Finding, error) {
	req := evidence.Request{EventID: snap.EventID, SnapshotVersion: snap.Version, Facts: []evidence.FactID{"F_DNS_ENCODED_LABEL"}, Hits: []evidence.Hit{r.Hit}, Quality: evidence.Quality{Coverage: evidence.CoverageComplete}}
	no := false
	req.Quality.CaptureTruncated = &no
	p := evidence.Provenance{Verified: true, Complete: true, Version: evidence.PhaseOneVersion, SourceIDs: []string{r.Hit.ID}}
	req.Inputs = []evidence.Input{{Scope: r.Hit.Scope, Window: &evidence.AnalysisWindow{Start: r.Hit.OccurredAt, End: r.Hit.OccurredAt.Add(time.Nanosecond)}, DNS: &evidence.DNSData{Provenance: p, Records: []evidence.DNSRecord{*r.DNS}}}}
	engine, _ := evidence.NewEngine(evidence.DefaultConfig())
	result, err := engine.Evaluate(ctx, req)
	return result.Findings, err
}
