package evidence

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
)

// ValidateSemanticResult rechecks cached outputs against the newly resolved
// plan. A matching hash alone must not bless corrupted references or strength.
func ValidateSemanticResult(plan SemanticPlan, result SemanticResult) error {
	if result.Plan.EventID != plan.EventID || result.Plan.SnapshotVersion != plan.SnapshotVersion || result.Plan.RuleVersion != plan.RuleVersion || result.Plan.InputMode != plan.InputMode || result.Plan.ContextSHA256 != plan.ContextSHA256 || !reflect.DeepEqual(result.Plan.Tasks, plan.Tasks) {
		return fmt.Errorf("cached semantic plan mismatch")
	}
	tasks := map[string]SemanticTask{}
	for _, t := range plan.Tasks {
		tasks[t.ID] = t
	}
	seen := map[string]bool{}
	if len(result.Plan.Executions) != len(plan.Executions) {
		return fmt.Errorf("cached semantic executions mismatch")
	}
	for n, expected := range plan.Executions {
		actual := result.Plan.Executions[n]
		if expected.Status == "planned" {
			if actual.Slot != expected.Slot || actual.SubjectID != expected.SubjectID || actual.TaskID != expected.TaskID || actual.Status != "accepted" || actual.Reason != "references_and_strength_validated" {
				return fmt.Errorf("invalid cached semantic execution")
			}
		} else if actual != expected {
			return fmt.Errorf("invalid cached semantic skip")
		}
	}
	for _, f := range result.Findings {
		task, ok := tasks[f.TaskID]
		if !ok || seen[f.TaskID] || f.Slot != task.Slot.Key || f.SubjectID != task.SubjectID || f.PropositionID != task.PropositionID || f.Scope != task.Scope || !sameSemanticWindow(f.Window, task.Window) || f.SnapshotVersion != plan.SnapshotVersion || f.RuleVersion != plan.RuleVersion || f.ExplanationOnly != task.Slot.ExplanationOnly || !reflect.DeepEqual(f.NonAdditiveWith, task.NonAdditiveWith) || validateSemanticItem(task, f.SemanticItem) != "" {
			return fmt.Errorf("invalid cached semantic finding")
		}
		seen[f.TaskID] = true
	}
	for _, t := range plan.Tasks {
		if !seen[t.ID] {
			return fmt.Errorf("missing cached semantic finding")
		}
	}
	return nil
}

func decodeSemanticResponse(raw string, maxBytes int) ([]SemanticItem, error) {
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("response too large")
	}
	// encoding/json normally accepts duplicate object keys; reject them explicitly.
	d := json.NewDecoder(strings.NewReader(raw))
	if err := scanSemanticJSON(d, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	d = json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	var envelope struct {
		Items []SemanticItem `json:"items"`
	}
	if err := d.Decode(&envelope); err != nil {
		return nil, err
	}
	if envelope.Items == nil || len(envelope.Items) > 23 {
		return nil, fmt.Errorf("missing/oversized items")
	}
	return envelope.Items, nil
}

func scanSemanticJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("JSON depth exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || keys[key] || key != strings.ToLower(key) {
				return fmt.Errorf("duplicate/non-string key")
			}
			keys[key] = true
			if err := scanSemanticJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := scanSemanticJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func semanticStrength(s string) int {
	switch s {
	case "none":
		return 0
	case "weak":
		return 1
	case "medium":
		return 2
	case "strong":
		return 3
	}
	return -1
}

func validateSemanticItem(task SemanticTask, item SemanticItem) string {
	if item.Judgement != "support" && item.Judgement != "contradict" && item.Judgement != "neutral" {
		return "invalid_judgement"
	}
	if semanticStrength(item.Strength) < 0 || semanticStrength(item.Strength) > semanticStrength(task.MaxStrength) || (item.Judgement == "neutral" && item.Strength != "none") || (task.Slot.ExplanationOnly && item.Strength != "none") {
		return "invalid_or_excessive_strength"
	}
	if strings.TrimSpace(item.Explanation) == "" || len(item.Explanation) > 2048 || len(item.Alternatives) > 8 || len(item.Gaps) > 8 {
		return "invalid_explanation_size"
	}
	for _, ss := range [][]string{item.Alternatives, item.Gaps} {
		for _, s := range ss {
			if len(s) > 512 {
				return "invalid_explanation_size"
			}
		}
	}
	if task.InputMode != SemanticRaw && redactSemanticText(item.Explanation) != item.Explanation {
		return "sensitive_model_output"
	}
	for _, ss := range [][]string{item.Alternatives, item.Gaps} {
		for _, s := range ss {
			if task.InputMode != SemanticRaw && redactSemanticText(s) != s {
				return "sensitive_model_output"
			}
		}
	}
	materials := map[string]DeliveredMaterial{}
	facts := map[string]bool{}
	adjudications := map[string]bool{}
	for _, m := range task.Materials {
		materials[m.ID] = m
		if m.AdjudicationID != "" {
			adjudications[m.AdjudicationID] = true
		}
	}
	for _, f := range task.Facts {
		facts[f.ID] = true
	}
	materialIDs := map[string]bool{}
	for id := range materials {
		materialIDs[id] = true
	}
	if !exactSemanticRefs(item.MaterialRefs, materialIDs) || !exactSemanticRefs(item.FactRefs, facts) || !exactSemanticRefs(item.AdjudicationRefs, adjudications) {
		return "undelivered_or_missing_reference"
	}
	if len(item.Quotes) == 0 || len(item.Quotes) > 32 {
		return "missing_or_excessive_quotes"
	}
	quoted := map[string]bool{}
	for _, q := range item.Quotes {
		m, ok := materials[q.MaterialID]
		if !ok || strings.TrimSpace(q.Excerpt) == "" || len(q.Excerpt) > 2048 || !strings.Contains(m.Text, q.Excerpt) {
			return "non_verbatim_or_undelivered_quote"
		}
		quoted[q.MaterialID] = true
	}
	key := task.Slot.Key
	if item.Strength == "strong" && (key.ID == "S01" || key.ID == "S02" || key.ID == "S10" || key.ID == "S11" || (key.ID == "S13" && key.Subtype == "command")) {
		request, response := false, false
		for _, m := range task.Materials {
			if quoted[m.ID] && (m.Kind == "protocol_request" || m.Kind == "stratum_request") {
				request = true
			}
			if quoted[m.ID] && (m.Kind == "protocol_response" || m.Kind == "stratum_response") {
				response = true
			}
		}
		if !request || !response {
			return "strong_requires_paired_quotes"
		}
	}
	for _, m := range task.Materials {
		if semanticPrimaryKind(key, m.Kind) && !quoted[m.ID] {
			return "missing_primary_material_quote"
		}
	}
	return ""
}

func semanticPrimaryKind(k SlotKey, kind string) bool {
	kinds := ""
	switch k.ID {
	case "S01":
		kinds = " protocol_request "
	case "S02", "S10":
		kinds = " protocol_request protocol_response "
	case "S03":
		kinds = " ua protocol_request "
	case "S04":
		kinds = " domain decoded_payload "
	case "S05":
		kinds = " page host "
	case "S06":
		kinds = " credential_fields protocol_request "
	case "S07":
		kinds = " protocol_request content_classification "
	case "S08":
		kinds = " chunk "
	case "S09":
		kinds = " protocol_request parsed_payload "
	case "S11":
		kinds = " stratum_request stratum_response "
	case "S12":
		if k.Subtype == "dga_lexical" {
			kinds = " domain "
		} else {
			kinds = " brand host "
		}
	case "S13":
		kinds = " decoded_payload "
		if k.Subtype == "command" {
			kinds += "protocol_request "
		} else {
			kinds += "operation_context "
		}
	case "S14":
		kinds = " protocol_request task_context "
	case "S15":
		kinds = " visibility gaps "
	case "BT-S01", "SC02":
		kinds = " group_member "
	case "SC01":
		kinds = " asset_role business_schedule time_distribution workhours_active "
	case "SC03":
		kinds = " brand credential_fields "
	case "R06", "R07":
		kinds = " history current_pattern "
	}
	return strings.Contains(kinds, " "+kind+" ")
}

func exactSemanticRefs(refs []string, allowed map[string]bool) bool {
	if len(refs) != len(allowed) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range refs {
		if !allowed[id] || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// Keep every interpretation for audit. Only mark positive duplicates; dissent
// and explanation-only items must remain visible to a report reviewer.
func dedupeSemanticFindings(findings []SemanticFinding) {
	type dedupeKey struct {
		Group, Proposition string
		Scope              Scope
		Start, End         string
	}
	winners := map[dedupeKey]int{}
	for i := range findings {
		f := &findings[i]
		if f.ExplanationOnly || f.Judgement != "support" || f.Strength == "none" {
			continue
		}
		group := ""
		for _, spec := range semanticSpecs {
			if spec.Key == f.Slot {
				group = spec.Deduplication
				break
			}
		}
		if group == "" {
			continue
		}
		key := dedupeKey{group, f.PropositionID, f.Scope, f.Window.Start.UTC().Format(time.RFC3339Nano), f.Window.End.UTC().Format(time.RFC3339Nano)}
		previous, ok := winners[key]
		if !ok || semanticStrength(f.Strength) > semanticStrength(findings[previous].Strength) {
			winners[key] = i
		}
	}
	for i := range findings {
		f := &findings[i]
		if f.ExplanationOnly || f.Judgement != "support" || f.Strength == "none" {
			continue
		}
		group := ""
		for _, spec := range semanticSpecs {
			if spec.Key == f.Slot {
				group = spec.Deduplication
				break
			}
		}
		key := dedupeKey{group, f.PropositionID, f.Scope, f.Window.Start.UTC().Format(time.RFC3339Nano), f.Window.End.UTC().Format(time.RFC3339Nano)}
		if winner, ok := winners[key]; ok && winner != i {
			f.DuplicateOf = findings[winner].TaskID
		}
	}
}
