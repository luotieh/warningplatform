package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

// EvidenceSourceRegistry is an audited backend import, never event/model data.
// Entries are reusable source bundles. Their window declares where the source
// is valid; report producers bind them to the exact observed scope/window.
type EvidenceSourceRegistry struct {
	Version string                `json:"version"`
	Entries []EvidenceSourceEntry `json:"entries"`
}

type EvidenceSourceEntry struct {
	ID               string                    `json:"id"`
	Authority        string                    `json:"authority"`
	ApprovedAt       time.Time                 `json:"approved_at"`
	Input            evidence.Input            `json:"input"`
	BaselineTraining *EvidenceBaselineTraining `json:"baseline_training,omitempty"`
}

type EvidenceBaselineTraining struct {
	evidence.Provenance
	Window                     evidence.AnalysisWindow `json:"window"`
	Samples                    int64                   `json:"samples"`
	NormalClassificationSource string                  `json:"normal_classification_source"`
	Population                 string                  `json:"population"` // full_normal_flows, never alert-only
}

func decodeEvidenceSources(raw []byte) (*EvidenceSourceRegistry, error) {
	if len(raw) > maxSupplementalBytes {
		return nil, errors.New("source_registry_budget_exceeded")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var r EvidenceSourceRegistry
	if err := d.Decode(&r); err != nil {
		return nil, errors.New("source_registry_invalid")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("source_registry_invalid")
	}
	if err := validateEvidenceSources(r); err != nil {
		return nil, err
	}
	return &r, nil
}

func validateEvidenceSources(r EvidenceSourceRegistry) error {
	if r.Version == "" || len(r.Entries) > 1024 {
		return errors.New("source_registry_invalid")
	}
	seen := map[string]bool{}
	for _, e := range r.Entries {
		if e.ID == "" || seen[e.ID] || e.Authority == "" || e.ApprovedAt.IsZero() || e.ApprovedAt.After(time.Now().UTC()) {
			return errors.New("source_registry_audit_invalid")
		}
		seen[e.ID] = true
		i := e.Input
		if i.Scope.AssetID == "" || i.Scope.EndpointID == "" || i.Scope.DeviceID == "" || i.Scope.GroupID != "" || i.Window == nil || !i.Window.Start.Before(i.Window.End) {
			return errors.New("source_registry_binding_invalid")
		}
		if i.DNS != nil && len(i.DNS.Records) > 0 || i.HTTP != nil && len(i.HTTP.Records) > 0 || i.Network != nil && (len(i.Network.Connections) > 0 || len(i.Network.Sessions) > 0) || i.TLS != nil && len(i.TLS.Records) > 0 {
			return errors.New("source_registry_contains_snapshot_observations")
		}
		// Reject overlapping bundles instead of allowing import order to decide
		// which adjudication, authorization or baseline the report believes.
		for _, previous := range r.Entries {
			if previous.ID == e.ID {
				break
			}
			if previous.Input.Scope == i.Scope && previous.Input.Window.Start.Before(i.Window.End) && i.Window.Start.Before(previous.Input.Window.End) {
				return errors.New("source_registry_overlap")
			}
		}
		trusted := func(p evidence.Provenance) bool { return trustedInputProvenance(p) }
		if len(i.Baselines) > 0 {
			t := e.BaselineTraining
			if t == nil || !trusted(t.Provenance) || t.Population != "full_normal_flows" || t.NormalClassificationSource == "" || t.Samples < 30 || !t.Window.Start.Before(t.Window.End) || t.Window.End.After(i.Window.Start) {
				return errors.New("source_registry_baseline_training_invalid")
			}
		}
		for _, b := range i.Baselines {
			if !trusted(b.Provenance) {
				return errors.New("source_registry_provenance_invalid")
			}
		}
		if i.DNS != nil && !trusted(i.DNS.Provenance) || i.HTTP != nil && !trusted(i.HTTP.Provenance) || i.Network != nil && !trusted(i.Network.Provenance) || i.TLS != nil && !trusted(i.TLS.Provenance) || i.History != nil && !trusted(i.History.Provenance) || i.Authorizations != nil && !trusted(i.Authorizations.Provenance) || i.Corroboration != nil && !trusted(i.Corroboration.Provenance) {
			return errors.New("source_registry_provenance_invalid")
		}
		if i.History != nil {
			h := i.History
			if !h.LookbackStart.Before(h.AsOf) {
				return errors.New("source_registry_history_invalid")
			}
			ids := map[string]bool{}
			for _, event := range h.Events {
				if event.ID == "" || ids[event.ID] || event.Time.Before(h.LookbackStart) || !event.Time.Before(h.AsOf) {
					return errors.New("source_registry_history_invalid")
				}
				ids[event.ID] = true
				if event.Adjudication != "unreviewed" && (event.AdjudicationID == "" || (event.Adjudication != "malicious" && event.Adjudication != "false_positive") || (event.AdjudicationSource != "human" && event.AdjudicationSource != "host_evidence" && event.AdjudicationSource != "authoritative_external")) {
					return errors.New("source_registry_adjudication_invalid")
				}
			}
			// Current-stage/campaign claims belong to an exact snapshot, not a
			// reusable registry. Preserve that independent evidence boundary.
			if h.CurrentStage != "" || h.CampaignID != "" || h.CurrentParametersVerified || h.GroupMembershipVerified {
				return errors.New("source_registry_requires_snapshot_proof")
			}
		}
	}
	return nil
}

// ImportEvidenceSources is intentionally backend-only; approval metadata must
// come from the importing operator/source, not a public verified=true field.
func (s Services) ImportEvidenceSources(ctx context.Context, raw []byte) error {
	r, err := decodeEvidenceSources(raw)
	if err != nil {
		return err
	}
	return s.Store.AggregationTransaction(ctx, "evidence_sources", func(tx store.Store) error {
		if err := putRecord(ctx, tx, "evidence_source_audit", digest(r), "", r); err != nil {
			return err
		}
		return putRecord(ctx, tx, "evidence_sources", "active", "", r)
	})
}

func (s Services) loadEvidenceSources(ctx context.Context) (*EvidenceSourceRegistry, *SnapshotInputIssue, error) {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	r, ok, err := s.Store.AggregateRecord(c, "evidence_sources", "active")
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		issue := snapshotIssueCause(SnapshotInputIssue{Code: "source_registry_read_failed", Stage: "load_sources", Retryable: true}, err)
		return nil, &issue, nil
	}
	if !ok {
		return nil, &SnapshotInputIssue{Code: "source_registry_not_configured", Stage: "load_sources"}, nil
	}
	sources, err := decodeEvidenceSources(r.Value)
	if err != nil {
		return nil, &SnapshotInputIssue{Code: err.Error(), Stage: "load_sources"}, nil
	}
	return sources, nil, nil
}

func produceSnapshotSupplemental(out *SnapshotEvidenceInput, snap EvidenceSnapshot, r *EvidenceSourceRegistry) {
	if r == nil {
		return
	}
	if err := validateEvidenceSources(*r); err != nil {
		out.Manifest.addIssue(SnapshotInputIssue{Code: err.Error(), Stage: "produce_sources"})
		return
	}
	extra := SnapshotSupplementalInputs{EventID: snap.EventID, SnapshotVersion: snap.Version, Version: digest(r)}
	inputs := append(append([]evidence.Input(nil), out.Request.Inputs...), out.Request.AssetInputs...)
	for _, target := range inputs {
		matched := false
		for _, entry := range r.Entries {
			if target.Scope != entry.Input.Scope {
				continue
			}
			if target.Window.Start.Before(entry.Input.Window.Start) || target.Window.End.After(entry.Input.Window.End) {
				continue
			}
			matched = true
			// Deep clone: filtering history must never mutate shared registry data.
			raw, _ := json.Marshal(entry.Input)
			var i evidence.Input
			_ = json.Unmarshal(raw, &i)
			i.Window = target.Window
			if h := i.History; h != nil {
				if h.AsOf.Before(target.Window.Start) || !h.LookbackStart.Before(target.Window.Start) {
					i.History = nil
					out.Manifest.addIssue(SnapshotInputIssue{Code: "source_history_coverage_gap", Stage: "produce_sources", Field: "history", Scope: target.Scope})
				} else {
					h.AsOf = target.Window.Start
					events := h.Events[:0]
					for _, e := range h.Events {
						if e.ID != snap.EventID && e.Time.Before(h.AsOf) {
							events = append(events, e)
						}
					}
					h.Events = events
				}
			}
			extra.Inputs = append(extra.Inputs, i)
		}
		if !matched {
			out.Manifest.addIssue(SnapshotInputIssue{Code: "source_scope_or_window_not_covered", Stage: "produce_sources", Scope: target.Scope})
		}
	}
	// Generated bundles live in the source audit journal, not evidence_inputs.
	// Do not claim a nonexistent exact-snapshot supplemental record as lineage.
	previousSupplementalVersion := out.Manifest.SupplementalVersion
	applySnapshotSupplemental(out, snap, &extra)
	out.Manifest.SupplementalVersion = previousSupplementalVersion
	out.Manifest.SourceRegistryVersion = digest(r)
}
