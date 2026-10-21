package service

import (
	"reflect"

	"vulnscan-backend/evidence"
)

// Separate published snapshots can repeat a session, but Session does not
// carry the original full transport tuple needed to merge their counters.
// Retain identical copies once; reject ambiguous identities before asset merge.
func resolveProviderSessionIdentities(out *SnapshotEvidenceInput) {
	type identity struct{ asset, device, session string }
	type record struct {
		scope evidence.Scope
		value evidence.Session
	}
	first := map[identity]record{}
	conflict := map[identity]bool{}
	for _, in := range out.Request.Inputs {
		if in.Network == nil || len(in.Network.Sessions) == 0 {
			continue
		}
		for _, session := range in.Network.Sessions {
			session.HitIDs = uniqueSortedStrings(append([]string(nil), session.HitIDs...))
			key := identity{in.Scope.AssetID, in.Scope.DeviceID, session.ID}
			old, exists := first[key]
			if !exists {
				first[key] = record{in.Scope, session}
			} else if old.scope != in.Scope || !reflect.DeepEqual(old.value, session) {
				conflict[key] = true
			}
		}
	}
	kept, reported := map[identity]bool{}, map[identity]bool{}
	for i := range out.Request.Inputs {
		in := &out.Request.Inputs[i]
		if in.Network == nil || len(in.Network.Sessions) == 0 {
			continue
		}
		remaining := []evidence.Session{}
		for _, session := range in.Network.Sessions {
			key := identity{in.Scope.AssetID, in.Scope.DeviceID, session.ID}
			if conflict[key] {
				if !reported[key] {
					out.Manifest.addIssue(SnapshotInputIssue{Code: "peer_session_identity_conflict", Stage: "session_summary", Field: "network.sessions", HitID: session.SourceID, Scope: in.Scope})
					reported[key] = true
				}
				continue
			}
			if !kept[key] {
				session.HitIDs = append([]string(nil), first[key].value.HitIDs...)
				remaining = append(remaining, session)
				kept[key] = true
			}
		}
		in.Network.Sessions = remaining
	}
}
