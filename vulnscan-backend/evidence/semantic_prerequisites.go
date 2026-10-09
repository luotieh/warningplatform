package evidence

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

func sameSemanticWindow(a, b AnalysisWindow) bool {
	return a.Start.Equal(b.Start) && a.End.Equal(b.End)
}

func validateSemanticRequest(r SemanticRequest) error {
	if semanticMode(r.InputMode) != SemanticRaw && semanticMode(r.InputMode) != SemanticRedacted {
		return fmt.Errorf("invalid semantic input mode")
	}
	if strings.TrimSpace(r.EventID) == "" || r.SnapshotVersion <= 0 {
		return fmt.Errorf("event_id and positive snapshot_version required")
	}
	ids := map[string]bool{}
	for _, s := range r.Subjects {
		if s.ID == "" || s.PropositionID == "" || ids[s.ID] {
			return fmt.Errorf("empty/duplicate subject or empty proposition")
		}
		ids[s.ID] = true
		if !validSemanticScope(s.Scope) || s.Window.Start.IsZero() || !s.Window.End.After(s.Window.Start) {
			return fmt.Errorf("subject %s has unresolved scope/window", s.ID)
		}
		mids := map[string]bool{}
		for _, m := range s.Materials {
			if m.ID == "" || mids[m.ID] || !knownMaterialKind(m.Kind) {
				return fmt.Errorf("subject %s has invalid/duplicate material", s.ID)
			}
			mids[m.ID] = true
			if m.Scope != s.Scope || m.SnapshotVersion != r.SnapshotVersion || !sameSemanticWindow(m.Window, s.Window) {
				return fmt.Errorf("material %s has cross-scope/snapshot/window binding", m.ID)
			}
		}
		fids := map[FactID]bool{}
		for _, f := range s.Facts {
			known := false
			for _, d := range Definitions() {
				if d.ID == f.FactID {
					known = true
					break
				}
			}
			if !known || fids[f.FactID] || f.SnapshotVersion != r.SnapshotVersion || f.Scope != s.Scope || f.Window == nil || !sameSemanticWindow(AnalysisWindow{f.Window.Start, f.Window.End}, s.Window) {
				return fmt.Errorf("subject %s has invalid fact binding", s.ID)
			}
			if f.Status != Observed && f.Status != NotObserved && f.Status != Missing {
				return fmt.Errorf("invalid fact status")
			}
			fids[f.FactID] = true
		}
	}
	return nil
}

func validSemanticScope(s Scope) bool {
	return s.GroupID != "" || (s.AssetID != "" && s.EndpointID != "" && s.DeviceID != "")
}

func knownMaterialKind(k string) bool {
	const kinds = " protocol_request protocol_response direction pair ua domain decode encoded_payload decoded_payload page host brand brand_authorization brand_relation credential_fields volume content_classification chunk transfer_join parsed_payload stratum_request stratum_response lexical_context operation_context asset_role task_context visibility gaps group_member business_schedule time_distribution workhours_active history current_pattern "
	return strings.Contains(kinds, " "+k+" ")
}

func trustedSemanticMaterial(m SemanticMaterial) bool {
	return trustedSemanticMaterialMode(m, SemanticRedacted)
}
func trustedSemanticMaterialMode(m SemanticMaterial, mode SemanticInputMode) bool {
	if !m.Provenance.Verified || m.Provenance.Version == "" || len(m.Provenance.SourceIDs) == 0 || (semanticMode(mode) != SemanticRaw && !m.Redacted) || strings.TrimSpace(m.Text) == "" || m.FieldPath == "" {
		return false
	}
	for _, id := range m.Provenance.SourceIDs {
		if strings.TrimSpace(id) == "" {
			return false
		}
	}
	return true
}

func observedSemanticFact(f Finding) bool {
	return f.Status == Observed && f.Eligibility == "eligible" && f.RuleVersion != "" && len(f.SourceIDs) > 0
}

// Select only a slot's prerequisites, not every supplied context or the catalog.
func resolveSemanticSlot(spec slotSpec, s SemanticSubject, eventID string) (materials []SemanticMaterial, facts []Finding, maxStrength, reason string, nonAdditive []string) {
	byID := map[string]SemanticMaterial{}
	byKind := map[string][]SemanticMaterial{}
	for _, m := range s.Materials {
		if trustedSemanticMaterialMode(m, s.InputMode) {
			byID[m.ID] = m
			byKind[m.Kind] = append(byKind[m.Kind], m)
		}
	}
	for _, kind := range spec.Kinds {
		if kind != "chunk" && kind != "volume" && kind != "group_member" && kind != "history" && len(byKind[kind]) > 1 {
			return nil, nil, "", "ambiguous_" + kind, nil
		}
	}
	selected := map[string]bool{}
	add := func(m SemanticMaterial) {
		if !selected[m.ID] {
			materials = append(materials, m)
			selected[m.ID] = true
		}
	}
	for _, kind := range spec.Kinds {
		ms := byKind[kind]
		if kind == "time_distribution" && len(ms) == 0 {
			ms = byKind["workhours_active"]
		}
		if len(ms) == 0 {
			return nil, nil, "", "missing_or_unverified_" + kind, nil
		}
		for _, m := range ms {
			add(m)
		}
	}
	fmap := map[FactID]Finding{}
	for _, f := range s.Facts {
		if observedSemanticFact(f) {
			fmap[f.FactID] = f
		}
	}
	for _, id := range spec.AllFacts {
		f, ok := fmap[id]
		if !ok {
			return nil, nil, "", "missing_observed_" + string(id), nil
		}
		facts = append(facts, f)
	}
	if len(spec.AnyFacts) > 0 {
		for _, id := range spec.AnyFacts {
			if f, ok := fmap[id]; ok {
				facts = append(facts, f)
			}
		}
		if len(facts) == 0 {
			return nil, nil, "", "missing_observed_action_or_coordination_fact", nil
		}
	}
	maxStrength = "strong"
	if spec.ExplanationOnly {
		maxStrength = "none"
	}
	// Pair proof is useful to S01/S13 even though it is not required at weak level.
	pair, pairMaterials := false, []SemanticMaterial(nil)
	needsPair := spec.Key.ID == "S01" || spec.Key.ID == "S02" || spec.Key.ID == "S10" || spec.Key.ID == "S11" || (spec.Key.ID == "S13" && spec.Key.Subtype == "command")
	if needsPair {
		pair, pairMaterials = semanticPair(byKind, byID)
	}
	if (spec.Key.ID == "S01" || (spec.Key.ID == "S13" && spec.Key.Subtype == "command")) && pair && pairMaterials[0].Kind != "protocol_request" {
		pair = false
	}
	if pair {
		for _, m := range pairMaterials {
			add(m)
		}
	}
	if spec.Key.ID == "S02" || spec.Key.ID == "S10" || spec.Key.ID == "S11" {
		if !pair {
			return nil, nil, "", "unresolved_bidirectional_pair", nil
		}
		if spec.Key.ID == "S11" && pairMaterials[0].Kind != "stratum_request" {
			return nil, nil, "", "unresolved_stratum_pair", nil
		}
		if spec.Key.ID != "S11" && pairMaterials[0].Kind != "protocol_request" {
			return nil, nil, "", "unresolved_protocol_pair", nil
		}
	}
	if spec.Key.ID == "S01" || (spec.Key.ID == "S13" && spec.Key.Subtype == "command") {
		if !pair {
			maxStrength = "medium"
		}
	}
	if len(byKind["decode"]) > 0 && (spec.Key.ID == "S04" || spec.Key.ID == "S13") {
		for _, d := range byKind["decode"] {
			chain, ok := semanticDecode(d, byID)
			if !ok {
				return nil, nil, "", "invalid_decode_chain", nil
			}
			for _, m := range chain {
				add(m)
			}
			if spec.Key.ID == "S04" && !semanticMaterialLinks(byKind["domain"], chain[0].ID) {
				return nil, nil, "", "unresolved_domain_decode", nil
			}
			if spec.Key.ID == "S13" && spec.Key.Subtype == "other" && !semanticMaterialLinks(byKind["operation_context"], chain[len(chain)-1].ID) {
				return nil, nil, "", "unresolved_decoded_operation", nil
			}
			if spec.Key.ID == "S13" && spec.Key.Subtype == "command" {
				linked := false
				for _, r := range byKind["protocol_request"] {
					for _, id := range r.RelatedIDs {
						if id == chain[len(chain)-1].ID {
							linked = true
						}
					}
				}
				if !linked {
					return nil, nil, "", "unresolved_decoded_request", nil
				}
			}
		}
	}
	switch spec.Key.ID {
	case "S06":
		if !semanticRequestFields(byKind["credential_fields"], byKind["protocol_request"]) {
			return nil, nil, "", "unresolved_request_fields", nil
		}
		nonAdditive = append(nonAdditive, "F_CRED_POST_STRUCTURE")
	case "S07":
		if !semanticUpload(byKind) {
			return nil, nil, "", "unresolved_complete_upload", nil
		}
	case "S08":
		if !semanticChunks(byKind, byID) {
			return nil, nil, "", "unresolved_chunk_sequence", nil
		}
	case "S09":
		for _, m := range byKind["protocol_request"] {
			if m.Method == "" || m.Destination == "" || m.Protocol == "" || !semanticDirection(byKind, m) {
				return nil, nil, "", "unresolved_parsed_request", nil
			}
		}
		if byKind["parsed_payload"][0].TransactionID != byKind["protocol_request"][0].TransactionID {
			return nil, nil, "", "unresolved_payload_request", nil
		}
	case "S11":
		for _, m := range byKind["stratum_request"] {
			if !strings.HasPrefix(m.Method, "mining.") || len(m.FieldNames) == 0 {
				return nil, nil, "", "missing_stratum_method_parameters", nil
			}
		}
		if !semanticStratum(pairMaterials[0], pairMaterials[1]) {
			return nil, nil, "", "invalid_stratum_messages", nil
		}
		nonAdditive = append(nonAdditive, "protocol.stratum")
	case "SC01":
		if byKind["asset_role"][0].Role == "" {
			return nil, nil, "", "missing_verified_asset_role", nil
		}
	case "S14", "S15":
		if len(s.Facts) == 0 {
			return nil, nil, "", "missing_accepted_facts", nil
		}
		facts = append([]Finding(nil), s.Facts...)
	case "BT-S01", "SC02":
		members := byKind["group_member"]
		if s.Scope.GroupID == "" || len(members) < 2 || len(members) > 5 {
			return nil, nil, "", "group_requires_2_to_5_verified_members", nil
		}
		assets := map[string]bool{}
		for _, m := range members {
			if m.AssetID == "" || m.Role == "" || assets[m.AssetID] {
				return nil, nil, "", "unresolved_group_members", nil
			}
			assets[m.AssetID] = true
		}
	case "R06", "R07":
		history := byKind["history"]
		if len(history) > 5 {
			return nil, nil, "", "history_limit_exceeded", nil
		}
		events, adjudications := map[string]bool{}, map[string]bool{}
		for _, m := range history {
			if m.EventID == "" || m.EventID == eventID || m.AdjudicationID == "" || events[m.EventID] || adjudications[m.AdjudicationID] || (m.AdjudicationSource != "human" && m.AdjudicationSource != "host_evidence" && m.AdjudicationSource != "authoritative_external") || (spec.Key.ID == "R07" && !m.FalsePositive) {
				return nil, nil, "", "invalid_independent_adjudication", nil
			}
			events[m.EventID], adjudications[m.AdjudicationID] = true, true
		}
	}
	if spec.Key.ID == "S01" || (spec.Key.ID == "S13" && spec.Key.Subtype == "command") {
		for _, m := range byKind["protocol_request"] {
			if !semanticDirection(byKind, m) {
				return nil, nil, "", "unresolved_direction", nil
			}
		}
	}
	if spec.Key.ID == "S05" || (spec.Key.ID == "S12" && spec.Key.Subtype == "brand_semantic_impostor") {
		if len(byKind["brand_relation"]) == 0 {
			maxStrength = "weak"
		} else {
			for _, m := range byKind["brand_relation"] {
				if len(m.RelatedIDs) < 2 {
					return nil, nil, "", "unresolved_brand_relation", nil
				}
				for _, id := range m.RelatedIDs {
					if _, ok := byID[id]; !ok {
						return nil, nil, "", "unresolved_brand_relation", nil
					}
				}
				if !semanticMaterialLinks([]SemanticMaterial{m}, byKind["host"][0].ID) || !semanticMaterialLinks([]SemanticMaterial{m}, byKind["brand_authorization"][0].ID) {
					return nil, nil, "", "unresolved_brand_relation", nil
				}
				add(m)
			}
		}
		nonAdditive = append(nonAdditive, "F_BRAND_IMPOSTOR", "F_URL_BRAND_SUBDOMAIN_TRICK")
	}
	if spec.Key.ID == "S03" {
		nonAdditive = append(nonAdditive, "F_HTTP_UA_RARITY")
	}
	if spec.Key.ID == "S12" && spec.Key.Subtype == "dga_lexical" {
		nonAdditive = append(nonAdditive, "F_DGA_LEXICAL")
		maxStrength = "weak"
	}
	// Actual parsed fields and authoritative records must be complete for these tasks.
	for _, m := range materials {
		if !m.Provenance.Complete || m.Truncated {
			if spec.Key.ID == "S07" || spec.Key.ID == "S08" || spec.Key.ID == "S06" || spec.Key.ID == "R06" || spec.Key.ID == "R07" {
				return nil, nil, "", "incomplete_required_material", nil
			}
			if !spec.ExplanationOnly {
				maxStrength = "weak"
			}
		}
	}
	return materials, facts, maxStrength, "", nonAdditive
}

func semanticStratum(request, response SemanticMaterial) bool {
	var req, resp map[string]json.RawMessage
	if json.Unmarshal([]byte(request.Text), &req) != nil || json.Unmarshal([]byte(response.Text), &resp) != nil {
		return false
	}
	var method string
	var params []json.RawMessage
	if json.Unmarshal(req["method"], &method) != nil || method != request.Method || json.Unmarshal(req["params"], &params) != nil || params == nil {
		return false
	}
	if len(req["id"]) == 0 || string(req["id"]) == "null" || len(resp["id"]) == 0 {
		return false
	}
	var requestID, responseID any
	requestDecoder := json.NewDecoder(strings.NewReader(string(req["id"])))
	requestDecoder.UseNumber()
	responseDecoder := json.NewDecoder(strings.NewReader(string(resp["id"])))
	responseDecoder.UseNumber()
	if requestDecoder.Decode(&requestID) != nil || responseDecoder.Decode(&responseID) != nil {
		return false
	}
	switch requestID.(type) {
	case string, json.Number:
	default:
		return false
	}
	switch responseID.(type) {
	case string, json.Number:
	default:
		return false
	}
	if requestID != responseID {
		return false
	}
	_, result := resp["result"]
	_, responseError := resp["error"]
	return result || responseError
}

func semanticMaterialLinks(materials []SemanticMaterial, id string) bool {
	for _, m := range materials {
		for _, linked := range m.RelatedIDs {
			if linked == id {
				return true
			}
		}
	}
	return false
}

func semanticDirection(byKind map[string][]SemanticMaterial, request SemanticMaterial) bool {
	if request.TransactionID == "" || (request.Direction != "outbound" && request.Direction != "inbound") {
		return false
	}
	for _, d := range byKind["direction"] {
		if d.TransactionID == request.TransactionID && d.Direction == request.Direction {
			return true
		}
	}
	return false
}

func semanticPair(kinds map[string][]SemanticMaterial, ids map[string]SemanticMaterial) (bool, []SemanticMaterial) {
	for _, p := range kinds["pair"] {
		if len(p.RelatedIDs) != 2 || !p.Provenance.Complete || p.Truncated {
			continue
		}
		a, aok := ids[p.RelatedIDs[0]]
		b, bok := ids[p.RelatedIDs[1]]
		if !aok || !bok || !a.Provenance.Complete || !b.Provenance.Complete || a.Truncated || b.Truncated {
			continue
		}
		if a.Kind == "protocol_response" || a.Kind == "stratum_response" {
			a, b = b, a
		}
		if !((a.Kind == "protocol_request" && b.Kind == "protocol_response") || (a.Kind == "stratum_request" && b.Kind == "stratum_response")) {
			continue
		}
		if a.TransactionID == "" || a.TransactionID != b.TransactionID || p.TransactionID != a.TransactionID || a.Direction == b.Direction || (a.Direction != "outbound" && a.Direction != "inbound") || (b.Direction != "outbound" && b.Direction != "inbound") {
			continue
		}
		return true, []SemanticMaterial{a, b, p}
	}
	return false, nil
}

func semanticDecode(d SemanticMaterial, ids map[string]SemanticMaterial) ([]SemanticMaterial, bool) {
	if len(d.DecodeSteps) == 0 || len(d.DecodeSteps) > 3 {
		return nil, false
	}
	var chain []SemanticMaterial
	previous := ""
	for _, step := range d.DecodeSteps {
		a, aok := ids[step.InputID]
		b, bok := ids[step.OutputID]
		if !aok || !bok || a.ID == b.ID || a.Truncated || b.Truncated || !a.Provenance.Complete || !b.Provenance.Complete || (previous != "" && previous != a.ID) {
			return nil, false
		}
		var decoded []byte
		var err error
		switch step.Encoding {
		case "base64":
			decoded, err = base64.StdEncoding.Strict().DecodeString(a.Text)
		case "base64url":
			decoded, err = base64.RawURLEncoding.Strict().DecodeString(a.Text)
		case "hex":
			decoded, err = hex.DecodeString(a.Text)
		default:
			return nil, false
		}
		if err != nil || string(decoded) != b.Text {
			return nil, false
		}
		chain = append(chain, a, b)
		previous = b.ID
	}
	if ids[previous].Kind != "decoded_payload" {
		return nil, false
	}
	return chain, true
}

func semanticRequestFields(fields, requests []SemanticMaterial) bool {
	for _, f := range fields {
		if f.TransactionID == "" || len(f.FieldNames) == 0 || f.Method == "" || f.Destination == "" {
			return false
		}
		matched := false
		for _, r := range requests {
			if r.TransactionID == f.TransactionID && r.Method == f.Method && r.Destination == f.Destination {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func semanticUpload(kinds map[string][]SemanticMaterial) bool {
	for _, r := range kinds["protocol_request"] {
		if r.TransactionID == "" || r.Direction != "outbound" || !semanticDirection(kinds, r) {
			continue
		}
		volume, classification := false, false
		for _, v := range kinds["volume"] {
			if v.TransactionID == r.TransactionID && v.Bytes != nil && *v.Bytes > 0 {
				volume = true
			}
		}
		for _, c := range kinds["content_classification"] {
			if c.TransactionID == r.TransactionID {
				classification = true
			}
		}
		if volume && classification {
			return true
		}
	}
	return false
}

func semanticChunks(kinds map[string][]SemanticMaterial, ids map[string]SemanticMaterial) bool {
	for _, join := range kinds["transfer_join"] {
		if len(join.RelatedIDs) < 2 {
			continue
		}
		transactions, sequences := map[string]bool{}, map[uint64]bool{}
		valid := true
		for _, id := range join.RelatedIDs {
			c, ok := ids[id]
			if !ok || c.Kind != "chunk" || c.TransactionID == "" || c.Sequence == nil || c.Bytes == nil || *c.Bytes == 0 || transactions[c.TransactionID] || sequences[*c.Sequence] {
				valid = false
				break
			}
			transactions[c.TransactionID], sequences[*c.Sequence] = true, true
			volume := false
			for _, v := range kinds["volume"] {
				if v.TransactionID == c.TransactionID && v.Bytes != nil && *v.Bytes == *c.Bytes {
					volume = true
				}
			}
			if !volume {
				valid = false
				break
			}
		}
		if valid {
			return true
		}
	}
	return false
}
