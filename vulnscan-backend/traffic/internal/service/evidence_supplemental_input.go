package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"vulnscan-backend/evidence"
)

const maxSupplementalBytes = 2 << 20

// SnapshotSupplementalInputs is a backend-only bridge for independently
// verified data sources. It is never decoded from an event, probe or LLM output.
// The exact-snapshot record must be produced by a trusted enrichment job.
// Version alone is not cache identity: the entire record is hashed.
type SnapshotSupplementalInputs struct {
	EventID         string                                 `json:"event_id"`
	SnapshotVersion int64                                  `json:"snapshot_version"`
	Version         string                                 `json:"version"`
	Inputs          []evidence.Input                       `json:"inputs"`
	Groups          []evidence.GroupInput                  `json:"groups"`
	Policies        map[evidence.FactID]map[string]float64 `json:"policies,omitempty"`
}

func (s Services) loadSnapshotSupplemental(ctx context.Context, snap EvidenceSnapshot) (*SnapshotSupplementalInputs, *SnapshotInputIssue, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	record, exists, err := s.Store.AggregateRecord(queryCtx, "evidence_inputs", snapshotKey(snap.EventID, snap.Version))
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		issue := snapshotIssueCause(SnapshotInputIssue{Code: "supplemental_read_failed", Stage: "load_supplemental", Retryable: true}, err)
		return nil, &issue, nil
	}
	if !exists {
		return nil, &SnapshotInputIssue{Code: "supplemental_not_configured", Stage: "load_supplemental"}, nil
	}
	issue := &SnapshotInputIssue{Code: "supplemental_record_invalid", Stage: "load_supplemental"}
	if len(record.Value) > maxSupplementalBytes {
		issue.Code = "supplemental_budget_exceeded"
		return nil, issue, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(record.Value))
	decoder.DisallowUnknownFields()
	var inputs SnapshotSupplementalInputs
	if err := decoder.Decode(&inputs); err != nil {
		return nil, issue, nil
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, issue, nil
	}
	if err := validateSnapshotSupplemental(snap, inputs); err != nil {
		return nil, issue, nil
	}
	return &inputs, nil, nil
}

// StoreSnapshotSupplemental persists a trusted enrichment result after identity
// and policy validation. This is deliberately not a public HTTP endpoint.
func (s Services) StoreSnapshotSupplemental(ctx context.Context, snap EvidenceSnapshot, inputs SnapshotSupplementalInputs) error {
	if err := validateSnapshotSupplemental(snap, inputs); err != nil {
		return err
	}
	raw, err := json.Marshal(inputs)
	if err != nil {
		return err
	}
	if len(raw) > maxSupplementalBytes {
		return errors.New("supplemental input budget exceeded")
	}
	return putRecord(ctx, s.Store, "evidence_inputs", snapshotKey(snap.EventID, snap.Version), snap.EventID, inputs)
}

func validateSnapshotSupplemental(snap EvidenceSnapshot, extra SnapshotSupplementalInputs) error {
	if extra.EventID != snap.EventID || extra.SnapshotVersion != snap.Version || extra.Version == "" {
		return errors.New("supplemental snapshot identity mismatch")
	}
	if len(extra.Inputs) > 1024 || len(extra.Groups) > 64 {
		return errors.New("supplemental scope budget exceeded")
	}
	cfg := evidence.DefaultConfig()
	cfg.Policies = extra.Policies
	if _, err := evidence.NewEngine(cfg); err != nil {
		return err
	}
	seen := map[evidence.Scope]bool{}
	seenGroups := map[string]bool{}
	for _, group := range extra.Groups {
		if group.ID == "" || seenGroups[group.ID] {
			return errors.New("invalid or repeated supplemental group")
		}
		seenGroups[group.ID] = true
	}
	for _, input := range extra.Inputs {
		if input.Scope.AssetID == "" || input.Scope.EndpointID == "" || input.Scope.DeviceID == "" || input.Scope.GroupID != "" || seen[input.Scope] || input.Window == nil || !input.Window.Start.Before(input.Window.End) {
			return errors.New("invalid supplemental scope/window")
		}
		seen[input.Scope] = true
		// Core observations are always built from committed hits; accepting an
		// alternate copy would let samples replace the complete denominator.
		if input.DNS != nil && len(input.DNS.Records) > 0 || input.HTTP != nil && len(input.HTTP.Records) > 0 || input.Network != nil && len(input.Network.Connections) > 0 {
			return errors.New("supplemental cannot replace core observations")
		}
	}
	return nil
}

func trustedInputProvenance(p evidence.Provenance) bool {
	if !p.Verified || !p.Complete || p.Version == "" || len(p.SourceIDs) == 0 {
		return false
	}
	for _, id := range p.SourceIDs {
		if id == "" {
			return false
		}
	}
	return true
}

func applySnapshotSupplemental(out *SnapshotEvidenceInput, snap EvidenceSnapshot, extra *SnapshotSupplementalInputs) {
	if extra == nil {
		return
	}
	if err := validateSnapshotSupplemental(snap, *extra); err != nil {
		out.Manifest.addIssue(SnapshotInputIssue{Code: "supplemental_record_invalid", Stage: "merge_supplemental"})
		return
	}
	out.Manifest.SupplementalVersion = digest(extra)
	bound := map[evidence.Scope]*evidence.Input{}
	hits := map[string]evidence.Hit{}
	for _, h := range out.Request.Hits {
		hits[h.ID] = h
	}
	for i := range out.Request.Inputs {
		input := &out.Request.Inputs[i]
		bound[input.Scope] = input
	}
	for i := range out.Request.AssetInputs {
		input := &out.Request.AssetInputs[i]
		bound[input.Scope] = input
	}
	for _, source := range extra.Inputs {
		target := bound[source.Scope]
		issue := func(code, field string) {
			out.Manifest.addIssue(SnapshotInputIssue{Code: code, Stage: "merge_supplemental", Field: field, Scope: source.Scope})
		}
		if target == nil || !source.Window.Start.Equal(target.Window.Start) || !source.Window.End.Equal(target.Window.End) {
			issue("supplemental_binding_mismatch", "scope/window")
			continue
		}
		accept := func(p evidence.Provenance, field string) bool {
			if !trustedInputProvenance(p) {
				issue("supplemental_provenance_unverified", field)
				return false
			}
			return true
		}
		for _, b := range source.Baselines {
			if accept(b.Provenance, "baselines") {
				kept := target.Baselines[:0]
				for _, old := range target.Baselines {
					if old.FactID != b.FactID {
						kept = append(kept, old)
					}
				}
				target.Baselines = kept
				target.Baselines = append(target.Baselines, b)
			}
		}
		if source.DNS != nil && accept(source.DNS.Provenance, "dns_lexical_corpus") && target.DNS != nil {
			target.DNS.BigramLogProbabilities = source.DNS.BigramLogProbabilities
		}
		if source.HTTP != nil && accept(source.HTTP.Provenance, "brand_registry") && target.HTTP != nil {
			target.HTTP.Brands = source.HTTP.Brands
			target.HTTP.BrandsVerified = source.HTTP.BrandsVerified
		}
		if source.Network != nil && accept(source.Network.Provenance, "network_enrichment") && target.Network != nil {
			n := source.Network
			target.Network.Services = n.Services
			target.Network.ServicesVerified = n.ServicesVerified
			target.Network.ASN = n.ASN
			target.Network.Country = n.Country
			target.Network.Reputation = n.Reputation
			for _, session := range n.Sessions {
				valid := session.VolumeVerified && session.ID != "" && session.SourceID != "" && !session.Start.Before(target.Window.Start) && !session.End.After(target.Window.End) && session.Start.Before(session.End) && len(session.HitIDs) > 0
				for _, id := range session.HitIDs {
					h, ok := hits[id]
					valid = valid && ok && h.Scope == source.Scope && !h.OccurredAt.Before(session.Start) && !h.OccurredAt.After(session.End)
				}
				if valid {
					target.Network.Sessions = append(target.Network.Sessions, session)
				} else {
					issue("supplemental_session_binding_invalid", "network.sessions")
				}
			}
		}
		if source.TLS != nil && accept(source.TLS.Provenance, "tls_enrichment") {
			valid := true
			for _, record := range source.TLS.Records {
				h, ok := hits[record.SourceID]
				valid = valid && ok && h.Scope == source.Scope && record.Time.Equal(h.OccurredAt)
			}
			if valid {
				copy := *source.TLS
				if len(copy.Records) == 0 && target.TLS != nil {
					copy.Records = target.TLS.Records
					copy.Complete = target.TLS.Complete
				}
				target.TLS = &copy
			} else {
				issue("supplemental_binding_mismatch", "tls.records")
			}
		}
		if source.History != nil && accept(source.History.Provenance, "history") {
			copy := *source.History
			target.History = &copy
		}
		if source.Authorizations != nil && accept(source.Authorizations.Provenance, "authorization_records") {
			copy := *source.Authorizations
			target.Authorizations = &copy
		}
		if source.Corroboration != nil && accept(source.Corroboration.Provenance, "independent_rule_and_intel_metadata") {
			copy := *source.Corroboration
			target.Corroboration = &copy
		}
	}
	for _, group := range extra.Groups {
		valid := group.ID != "" && trustedInputProvenance(group.Provenance) && group.Window.Start.Before(group.Window.End) && len(group.Members) >= 3
		members := map[string]bool{}
		for _, member := range group.Members {
			valid = valid && member.MembershipVerified && member.AssetID == member.Scope.AssetID && bound[member.Scope] != nil && !members[member.AssetID] && len(member.HitIDs) > 0
			members[member.AssetID] = true
			for _, id := range member.HitIDs {
				h, ok := hits[id]
				valid = valid && ok && h.Scope == member.Scope && !h.OccurredAt.Before(group.Window.Start) && h.OccurredAt.Before(group.Window.End)
			}
		}
		if valid {
			out.Request.Groups = append(out.Request.Groups, group)
		} else {
			out.Manifest.addIssue(SnapshotInputIssue{Code: "supplemental_group_binding_invalid", Stage: "merge_supplemental", Field: fmt.Sprintf("groups.%s", group.ID)})
		}
	}
	// Presence of a bundle is not proof every dependency was supplied. Keep a
	// conservative inventory; individual rule findings explain exact readiness.
	out.Manifest.MissingInputs = snapshotMissingFamilies(out.Request)
}

func snapshotMissingFamilies(req evidence.Request) []string {
	out := []string{}
	checks := []struct {
		name    string
		present func(evidence.Input) bool
	}{
		{"baselines", func(i evidence.Input) bool { return len(i.Baselines) > 0 }},
		{"history", func(i evidence.Input) bool { return i.History != nil }},
		{"campaign_and_stage_proofs", func(i evidence.Input) bool {
			return i.History != nil && trustedInputProvenance(i.History.CurrentStageProvenance) && trustedInputProvenance(i.History.CampaignProvenance)
		}},
		{"authorization_records", func(i evidence.Input) bool { return i.Authorizations != nil }},
		{"tls_trust_and_fingerprint_registry", func(i evidence.Input) bool {
			return i.TLS != nil && i.TLS.IssuersVerified && i.TLS.ExceptionsVerified && i.TLS.FingerprintsVerified
		}},
		{"independent_rule_and_intel_metadata", func(i evidence.Input) bool { return i.Corroboration != nil }},
		{"brand_registry", func(i evidence.Input) bool { return i.HTTP != nil && i.HTTP.BrandsVerified }},
		{"service_registry", func(i evidence.Input) bool { return i.Network != nil && i.Network.ServicesVerified }},
	}
	for _, check := range checks {
		for _, i := range req.Inputs {
			if !check.present(i) {
				out = append(out, check.name)
				break
			}
		}
	}
	if len(req.Groups) == 0 {
		out = append(out, "group_membership")
	}
	return out
}
