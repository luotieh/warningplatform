package service

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"vulnscan-backend/evidence"
)

// Completeness is local to a family and scope, never a bundle-wide gate.
// SourceIdentity pins the current snapshot; historical versions remain in
// Manifest.PhaseOne.Sources and History.FrozenSnapshots.
type PreparedFamilyCoverage struct {
	Family         string                   `json:"family"`
	Scope          evidence.Scope           `json:"scope"`
	Window         *evidence.AnalysisWindow `json:"window"`
	IOCValues      []string                 `json:"ioc_values"`
	SourceIdentity string                   `json:"source_identity"`
	SourceIDs      []string                 `json:"source_ids"`
	Available      bool                     `json:"available"`
	Verified       bool                     `json:"verified"`
	Complete       bool                     `json:"complete"`
	Reasons        []string                 `json:"reasons"`
}

func preparedFamilyCoverage(v EvidencePreparedInputs) []PreparedFamilyCoverage {
	out := []PreparedFamilyCoverage{}
	for _, set := range [][]evidence.Input{v.Request.Inputs, v.Request.AssetInputs} {
		for _, in := range set {
			for _, family := range []string{"DNS", "HTTP", "Network", "TLS", "History", "PlatformHistory", "Corroboration", "Authorizations"} {
				rv := reflect.ValueOf(in).FieldByName(family)
				c := PreparedFamilyCoverage{Family: family, Scope: in.Scope, Window: in.Window,
					SourceIdentity: fmt.Sprintf("%s:%d:%d:%d", v.Request.EventID, v.Manifest.SnapshotVersion, v.Manifest.Watermark, v.Manifest.RevisionWatermark),
					SourceIDs:      []string{}, IOCValues: []string{}, Reasons: []string{}}
				// PlatformHistory is deliberately held outside Request's JSON.
				if family == "PlatformHistory" {
					rv = reflect.ValueOf(v.PlatformHistory[scopeKey(in.Scope)])
				}
				if rv.IsValid() && !rv.IsNil() {
					p := rv.Elem().FieldByName("Provenance").Interface().(evidence.Provenance)
					c.Available, c.Verified, c.Complete, c.SourceIDs = true, p.Verified, p.Complete, p.SourceIDs
					if !p.Verified {
						c.Reasons = append(c.Reasons, "unverified_family")
					}
					if !p.Complete {
						c.Reasons = append(c.Reasons, "partial_family")
					}
				} else {
					c.Reasons = append(c.Reasons, "family_not_supplied")
				}
				if v.Manifest.PhaseOne != nil {
					for _, b := range v.Manifest.PhaseOne.Bindings {
						if b.Scope == in.Scope && b.Verified {
							c.IOCValues = append(c.IOCValues, b.IOCType+":"+b.IOCValue)
						}
					}
				}
				c.IOCValues = uniqueSortedStrings(c.IOCValues)
				out = append(out, c)
			}
		}
	}
	return out
}

func uniqueSortedStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func (b PreparedEvidenceBundle) validateContractRelations() error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if len(raw) > preprocessDecodedBytes {
		return fmt.Errorf("prepared_bundle_budget_exceeded")
	}
	scopeOK := func(s evidence.Scope) bool { return s.AssetID != "" && s.DeviceID != "" && s.EndpointID != "" }
	sources := map[string]evidence.Hit{}
	scopes := map[evidence.Scope]bool{}
	for _, h := range b.Inputs.Request.Hits {
		if h.ID == "" || h.OccurredAt.IsZero() || !scopeOK(h.Scope) {
			return fmt.Errorf("prepared_invalid_hit_scope_or_time")
		}
		if _, ok := sources[h.ID]; ok {
			return fmt.Errorf("prepared_duplicate_hit_source")
		}
		sources[h.ID] = h
		scopes[h.Scope] = true
	}
	for _, set := range [][]evidence.Input{b.Inputs.Request.Inputs, b.Inputs.Request.AssetInputs} {
		for _, in := range set {
			if !scopeOK(in.Scope) || in.Window == nil || !in.Window.Start.Before(in.Window.End) {
				return fmt.Errorf("prepared_invalid_input_scope_or_window")
			}
			scopes[in.Scope] = true
			transactions := map[string]bool{}
			if in.HTTP != nil {
				for _, r := range in.HTTP.Records {
					h, ok := sources[r.SourceID]
					if !ok || h.Scope.AssetID != in.Scope.AssetID || h.Scope.DeviceID != in.Scope.DeviceID {
						return fmt.Errorf("prepared_http_source_scope_mismatch")
					}
					if r.TransactionID != "" {
						transactions[r.TransactionID] = true
					}
					if r.Time.Before(in.Window.Start) || !r.Time.Before(in.Window.End) {
						return fmt.Errorf("prepared_http_time_outside_window")
					}
				}
				for _, r := range in.HTTP.Records {
					if r.RedirectVerified && (r.TransactionID == "" || !transactions[r.RedirectToTransactionID]) {
						return fmt.Errorf("prepared_http_redirect_incomplete")
					}
					if r.ResponseVerified && (r.TransactionID == "" || r.ResponseStatus == 0) {
						return fmt.Errorf("prepared_http_response_incomplete")
					}
				}
			}
			if in.DNS != nil {
				for _, r := range in.DNS.Records {
					h, ok := sources[r.SourceID]
					if !ok || h.Scope.AssetID != in.Scope.AssetID || h.Scope.DeviceID != in.Scope.DeviceID {
						return fmt.Errorf("prepared_dns_source_scope_mismatch")
					}
					if r.Time.Before(in.Window.Start) || !r.Time.Before(in.Window.End) {
						return fmt.Errorf("prepared_dns_time_outside_window")
					}
				}
			}
		}
	}
	p := b.Inputs.Manifest.PhaseOne
	seenSource := map[string]bool{}
	for _, s := range p.Sources {
		k := snapshotKey(s.EventID, s.Version)
		if seenSource[k] {
			return fmt.Errorf("prepared_duplicate_snapshot_source")
		}
		seenSource[k] = true
	}
	bindings := map[string]bool{}
	for _, x := range p.Bindings {
		h, ok := sources[x.SourceID]
		if x.Verified && (!ok || h.Scope != x.Scope || x.Field == "" || x.IOCType == "" || x.IOCValue == "") {
			return fmt.Errorf("prepared_ioc_cross_object_binding")
		}
		if x.Verified {
			if x.IOCType == "ip" {
				u, err := url.Parse(x.Scope.EndpointID)
				if err != nil || u.Hostname() != x.IOCValue {
					return fmt.Errorf("prepared_ip_endpoint_binding_mismatch")
				}
			}
			for _, record := range p.Records {
				if record.Hit.ID != x.SourceID {
					continue
				}
				switch x.Field {
				case "http.request.host":
					if record.HTTP == nil {
						return fmt.Errorf("prepared_ioc_protocol_field_missing")
					}
					u, err := url.Parse(record.HTTP.URL)
					if err != nil || !strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), strings.TrimSuffix(x.IOCValue, ".")) {
						return fmt.Errorf("prepared_ioc_http_field_mismatch")
					}
				case "http.request.url":
					if record.HTTP == nil || record.HTTP.URL != x.IOCValue {
						return fmt.Errorf("prepared_ioc_url_field_mismatch")
					}
				case "dns.question.name":
					if record.DNS == nil || !strings.EqualFold(strings.TrimSuffix(record.DNS.Domain, "."), strings.TrimSuffix(x.IOCValue, ".")) {
						return fmt.Errorf("prepared_ioc_dns_field_mismatch")
					}
				}
			}
			bindings[scopeKey(x.Scope)+"|"+x.IOCType+"|"+x.IOCValue] = true
		}
	}
	for _, set := range [][]PhaseOneContact{p.CurrentContacts, p.Contacts} {
		seen := map[string]bool{}
		for _, c := range set {
			if c.ID == "" || seen[c.ID] {
				return fmt.Errorf("prepared_duplicate_contact")
			}
			seen[c.ID] = true
			if !bindings[scopeKey(c.Scope)+"|"+c.IOCType+"|"+c.IOCValue] {
				return fmt.Errorf("prepared_contact_ioc_binding_missing")
			}
			switch c.Kind {
			case "tcp_initiation", "dns_question", "complete_http_request":
			default:
				return fmt.Errorf("prepared_invalid_contact_unit: %s", c.Kind)
			}
		}
	}
	for _, s := range b.Inputs.SemanticMaterials.Subjects {
		if !scopes[s.Scope] || !s.Window.Start.Before(s.Window.End) {
			return fmt.Errorf("prepared_invalid_semantic_scope_or_window")
		}
		ids := map[string]evidence.SemanticMaterial{}
		for _, m := range s.Materials {
			if _, ok := ids[m.ID]; ok {
				return fmt.Errorf("prepared_duplicate_material")
			}
			ids[m.ID] = m
			if m.Scope != s.Scope || m.SnapshotVersion != b.Snapshot.Version || m.Window != s.Window {
				return fmt.Errorf("prepared_material_subject_binding_mismatch")
			}
			if m.Provenance.Verified && (m.Provenance.Version == "" || len(m.Provenance.SourceIDs) == 0) {
				return fmt.Errorf("prepared_untraceable_material")
			}
			seen := map[string]bool{}
			for _, id := range m.Provenance.SourceIDs {
				if seen[id] {
					return fmt.Errorf("prepared_duplicate_material_source")
				}
				seen[id] = true
				// Historical/registry material is bound by its separate provenance;
				// protocol and decode material must originate in a current hit.
				switch m.Kind {
				case "protocol_request", "protocol_response", "parsed_payload", "encoded_payload", "decoded_payload", "domain", "direction", "host", "ua":
					if _, ok := sources[id]; !ok {
						return fmt.Errorf("prepared_forged_material_source")
					}
				}
			}
		}
		for _, m := range s.Materials {
			for _, step := range m.DecodeSteps {
				if _, ok := ids[step.InputID]; !ok {
					return fmt.Errorf("prepared_decode_relation_missing")
				}
				if _, ok := ids[step.OutputID]; !ok {
					return fmt.Errorf("prepared_decode_relation_missing")
				}
			}
		}
	}
	expected := preparedFamilyCoverage(b.Inputs)
	if digest(expected) != digest(b.Coverage) {
		return fmt.Errorf("prepared_family_coverage_mismatch")
	}
	return nil
}

// Validates the complete ledger without calling a report generator or Store.
func ValidatePreparedExecution(b PreparedEvidenceBundle, out PreparedEvidenceExecution) error {
	if b.InputDigest == "" {
		return fmt.Errorf("normalized_input_digest_missing")
	}
	return validateNormalizedLedger(out)
}

func validateNormalizedLedger(out PreparedEvidenceExecution) error {
	if out.Contract == nil || out.Contract.InputDigest == "" {
		return fmt.Errorf("normalized_input_digest_missing")
	}
	n := out.Evidence.Normalized
	ids, catalog := map[string]bool{}, map[string]bool{}
	points := 0
	for _, x := range n.Items {
		key, ok := out.Contract.SourceIndex[x.ID]
		if !ok || digest(out.Contract.SourceSets[key]) != digest(x.SourceIDs) {
			return fmt.Errorf("normalized_source_index_mismatch: %s", x.ID)
		}
		if x.Kind == "semantic" && x.ExecutionStatus == "accepted" && x.ModelVersion == "" {
			return fmt.Errorf("normalized_model_version_missing")
		}
		if x.ID == "" || ids[x.ID] {
			return fmt.Errorf("normalized_duplicate_instance: %s kind=%s rule=%s scope=%+v", x.ID, x.Kind, x.RuleID, x.Scope)
		}
		ids[x.ID] = true
		if x.Kind != "joint" {
			catalog[x.Kind+":"+x.RuleID] = true
			if x.ScoreContribution != 0 {
				return fmt.Errorf("normalized_non_joint_score")
			}
		}
		if x.TerminalStatus == "missing" && x.ScoreContribution != 0 {
			return fmt.Errorf("normalized_missing_score")
		}
		if x.ScoreContribution < 0 || (x.DuplicateOf != "" && x.ScoreContribution != 0) {
			return fmt.Errorf("normalized_invalid_contribution")
		}
		points += x.ScoreContribution
	}
	for _, id := range evidence.SupportedFacts() {
		if !catalog["fact:"+string(id)] {
			return fmt.Errorf("normalized_catalog_mismatch: %s", id)
		}
	}
	for _, d := range evidence.SemanticDefinitions() {
		if !catalog["semantic:"+d.Key.String()] {
			return fmt.Errorf("normalized_catalog_mismatch: %s", d.Key.String())
		}
	}
	if out.Evidence.PhaseOne == nil || points != out.Evidence.PhaseOne.Result.Score {
		return fmt.Errorf("normalized_joint_score_mismatch")
	}
	if _, err := json.Marshal(n); err != nil {
		return fmt.Errorf("normalized_invalid_number: %w", err)
	}
	if out.Contract == nil || out.Contract.InputDigest == "" {
		return fmt.Errorf("normalized_input_digest_missing")
	}
	return nil
}
