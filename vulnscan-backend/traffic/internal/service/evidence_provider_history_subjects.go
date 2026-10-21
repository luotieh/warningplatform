package service

import (
	"fmt"
	"sort"

	"vulnscan-backend/evidence"
)

// Build one independently bound subject per actual current IOC. Related rows
// feed infrastructure association only; primary temporal samples stay separate.
func populateProviderHistorySubjects(out *SnapshotEvidenceInput, snap EvidenceSnapshot, history ReportHistory) {
	if history.Status != "available" || out.Manifest.PhaseOne == nil {
		return
	}
	for n := range out.Request.Inputs {
		in := &out.Request.Inputs[n]
		byIOC := map[string]*evidence.HistorySubject{}
		for _, b := range out.Manifest.PhaseOne.CurrentBindings {
			if !b.Verified || b.Scope != in.Scope {
				continue
			}
			if b.IOCType != "ip" && b.IOCType != "domain" && b.IOCType != "url" {
				continue
			}
			key := b.IOCType + "\x00" + b.IOCValue
			s := byIOC[key]
			if s == nil {
				s = &evidence.HistorySubject{IOCType: b.IOCType, IOCValue: b.IOCValue, History: &evidence.HistoryData{
					PlatformRecords: true, IOC: b.IOCValue, Endpoint: in.Scope.EndpointID,
					AsOf: history.End, LookbackStart: history.Start,
					Provenance: evidence.Provenance{Verified: true, Complete: false, Version: "provider-history-subject-1:" + digest([]any{history, b.Scope, b.IOCType, b.IOCValue}), SourceIDs: []string{snapshotKey(snap.EventID, snap.Version)}},
				}}
				byIOC[key] = s
			}
			s.CurrentSourceIDs = append(s.CurrentSourceIDs, b.SourceID)
		}
		keys := []string{}
		for key := range byIOC {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		in.PlatformHistorySubjects = nil
		for _, key := range keys {
			s := byIOC[key]
			s.CurrentSourceIDs = uniqueSortedStrings(s.CurrentSourceIDs)
			seen := map[string]bool{}
			for _, rows := range [][]ReportHistoryRow{history.Rows, history.RelatedRows} {
				for _, row := range rows {
					if seen[row.EventID] || row.EventID == "" || in.Window == nil || !row.Last.Before(in.Window.Start) {
						continue
					}
					matched := false
					for _, ioc := range row.ActivityIOCs {
						matched = matched || ioc.Type == s.IOCType && ioc.Value == s.IOCValue
					}
					if !matched || len(row.AllAssetIDs) != 1 {
						continue
					}
					seen[row.EventID] = true
					s.History.Events = append(s.History.Events, evidence.HistoryEvent{Endpoint: row.DestinationEndpoint, ID: row.EventID, DeviceID: row.DeviceID, AssetID: row.AllAssetIDs[0], AssetIDs: row.AllAssetIDs, IOCType: s.IOCType, IOC: s.IOCValue, Time: row.First, Relation: row.Relation, ActivityType: row.ActivityType, ObservationKind: "event_occurrence"})
					s.History.SourceIDs = append(s.History.SourceIDs, row.EventID)
				}
			}
			sort.Slice(s.History.Events, func(i, j int) bool { return s.History.Events[i].ID < s.History.Events[j].ID })
			s.History.SourceIDs = uniqueSortedStrings(s.History.SourceIDs)
			in.PlatformHistorySubjects = append(in.PlatformHistorySubjects, *s)
		}
	}
}

// Private fields do not survive Request JSON. Validate both their serialized
// location and the producer's current binding, not just the subject's labels.
func validatePreparedHistorySubjects(v EvidencePreparedInputs) error {
	hits := map[string]evidence.Hit{}
	for _, h := range v.Request.Hits {
		hits[h.ID] = h
	}
	bindings := map[string]bool{}
	if m := v.Manifest.PhaseOne; m != nil {
		for _, b := range m.CurrentBindings {
			if b.Verified {
				bindings[scopeKey(b.Scope)+"\x00"+b.IOCType+"\x00"+b.IOCValue+"\x00"+b.SourceID] = true
			}
		}
	}
	known := map[string]bool{}
	for _, in := range v.Request.Inputs {
		key := scopeKey(in.Scope)
		known[key] = true
		in.PlatformHistorySubjects = v.PlatformHistorySubjects[key]
		if err := evidence.ValidateHistorySubjects(&in, hits); err != nil {
			return err
		}
		for _, s := range in.PlatformHistorySubjects {
			for _, id := range s.CurrentSourceIDs {
				if !bindings[key+"\x00"+s.IOCType+"\x00"+s.IOCValue+"\x00"+id] {
					return fmt.Errorf("prepared_history_subject_binding_mismatch")
				}
			}
		}
	}
	for key, subjects := range v.PlatformHistorySubjects {
		if !known[key] && len(subjects) > 0 {
			return fmt.Errorf("prepared_history_subject_unknown_scope")
		}
	}
	return nil
}
