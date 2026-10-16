package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"vulnscan-backend/evidence"
)

// Schema generation uses the actual Go wire types, including flattened
// embedded Provenance and capitalized untagged legacy fields. It never
// exposes json:"-" HTTP payloads as if they survived Request serialization.
func schemaForGo(t reflect.Type) map[string]any {
	defs := map[string]any{}
	var node func(reflect.Type) map[string]any
	nullable := func(v map[string]any) map[string]any {
		return map[string]any{"anyOf": []any{v, map[string]any{"type": "null"}}}
	}
	var fields func(reflect.Type, map[string]any, *[]string)
	fields = func(t reflect.Type, p map[string]any, required *[]string) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			tag := strings.Split(f.Tag.Get("json"), ",")
			if tag[0] == "-" || f.Type.Kind() == reflect.Func {
				continue
			}
			if f.Anonymous && tag[0] == "" {
				fields(f.Type, p, required)
				continue
			}
			name := tag[0]
			if name == "" {
				name = f.Name
			}
			p[name] = node(f.Type)
			if !strings.Contains(f.Tag.Get("json"), "omitempty") {
				*required = append(*required, name)
			}
		}
	}
	node = func(t reflect.Type) map[string]any {
		if t == reflect.TypeOf(time.Time{}) {
			return map[string]any{"type": "string", "format": "date-time"}
		}
		switch t.Kind() {
		case reflect.Pointer:
			return nullable(node(t.Elem()))
		case reflect.Struct:
			h := sha256.Sum256([]byte(t.PkgPath() + "." + t.Name()))
			key := t.Name() + "_" + hex.EncodeToString(h[:4])
			if _, ok := defs[key]; !ok {
				defs[key] = map[string]any{}
				p := map[string]any{}
				required := []string{}
				fields(t, p, &required)
				defs[key] = map[string]any{"type": "object", "properties": p, "required": required, "additionalProperties": false}
			}
			return map[string]any{"$ref": "#/$defs/" + key}
		case reflect.Slice:
			if t.Elem().Kind() == reflect.Uint8 {
				return nullable(map[string]any{"type": "string", "contentEncoding": "base64"})
			}
			return nullable(map[string]any{"type": "array", "items": node(t.Elem())})
		case reflect.Array:
			return map[string]any{"type": "array", "items": node(t.Elem()), "minItems": t.Len(), "maxItems": t.Len()}
		case reflect.Map:
			return nullable(map[string]any{"type": "object", "additionalProperties": node(t.Elem())})
		case reflect.Interface:
			return map[string]any{}
		case reflect.String:
			return map[string]any{"type": "string"}
		case reflect.Bool:
			return map[string]any{"type": "boolean"}
		case reflect.Float32, reflect.Float64:
			return map[string]any{"type": "number"}
		default:
			return map[string]any{"type": "integer"}
		}
	}
	root := node(t)
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["$defs"] = defs
	return root
}

func PreparedEvidenceJSONSchema() map[string]any {
	s := schemaForGo(reflect.TypeOf(PreparedEvidenceBundle{}))
	root := s["$defs"].(map[string]any)[strings.TrimPrefix(s["$ref"].(string), "#/$defs/")].(map[string]any)
	props := root["properties"].(map[string]any)
	props["schema_version"] = map[string]any{"const": PreparedEvidenceSchemaVersion}
	props["preprocess_version"] = map[string]any{"const": evidencePreprocessVersion}
	return s
}

// Includes execution metadata and the complete existing report evidence ledger;
// no duplicate F/S/C output model is introduced.
func NormalizedExecutionJSONSchema() map[string]any {
	return schemaForGo(reflect.TypeOf(PreparedEvidenceExecution{}))
}

// Validate presence and shape against the generated schema. Concrete value,
// identity, budget and algorithm gates remain typed checks, not schema claims.
func validatePreparedWire(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	schema := PreparedEvidenceJSONSchema()
	defs := schema["$defs"].(map[string]any)
	var visit func(any, map[string]any, string) error
	visit = func(v any, s map[string]any, path string) error {
		if r, ok := s["$ref"].(string); ok {
			return visit(v, defs[strings.TrimPrefix(r, "#/$defs/")].(map[string]any), path)
		}
		if alternatives, ok := s["anyOf"].([]any); ok {
			for _, a := range alternatives {
				if visit(v, a.(map[string]any), path) == nil {
					return nil
				}
			}
			return fmt.Errorf("prepared_schema_invalid_type: %s", path)
		}
		if c, ok := s["const"]; ok && v != c {
			return fmt.Errorf("prepared_schema_invalid_constant: %s", path)
		}
		switch s["type"] {
		case "null":
			if v != nil {
				return fmt.Errorf("expected null")
			}
		case "object":
			object, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("expected object %s", path)
			}
			props, _ := s["properties"].(map[string]any)
			if required, ok := s["required"].([]string); ok {
				for _, key := range required {
					if _, present := object[key]; !present {
						return fmt.Errorf("prepared_schema_required: %s.%s", path, key)
					}
				}
			}
			for key, item := range object {
				if p, ok := props[key]; ok {
					if err := visit(item, p.(map[string]any), path+"."+key); err != nil {
						return err
					}
				} else if a, ok := s["additionalProperties"].(map[string]any); ok {
					if err := visit(item, a, path+"."+key); err != nil {
						return err
					}
				} else if s["additionalProperties"] == false {
					return fmt.Errorf("prepared_schema_unknown_field: %s.%s", path, key)
				}
			}
		case "array":
			values, ok := v.([]any)
			if !ok {
				return fmt.Errorf("expected array %s", path)
			}
			for _, x := range values {
				if err := visit(x, s["items"].(map[string]any), path+"[]"); err != nil {
					return err
				}
			}
		case "string":
			if _, ok := v.(string); !ok {
				return fmt.Errorf("expected string %s", path)
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("expected bool %s", path)
			}
		case "integer", "number":
			if _, ok := v.(float64); !ok {
				return fmt.Errorf("expected number %s", path)
			}
		}
		return nil
	}
	return visit(value, schema, "bundle")
}

type PreparedFieldMapping struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Families      []string `json:"input_families"`
	JSONPaths     []string `json:"available_typed_field_paths"`
	ScopeFields   []string `json:"scope_fields"`
	GateAuthority string   `json:"gate_authority"`
}

// Every path is walked against a real type, rather than maintained in JSON.
func jsonLeafPaths(t reflect.Type, prefix string) []string {
	if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
		return []string{prefix}
	}
	if t.Kind() == reflect.Pointer {
		return jsonLeafPaths(t.Elem(), prefix)
	}
	if t == reflect.TypeOf(time.Time{}) {
		return []string{prefix}
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		return jsonLeafPaths(t.Elem(), prefix+"[]")
	case reflect.Map:
		return jsonLeafPaths(t.Elem(), prefix+".*")
	case reflect.Struct:
		out := []string{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" || f.Type.Kind() == reflect.Func {
				continue
			}
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag == "-" {
				continue
			}
			if f.Anonymous && tag == "" {
				out = append(out, jsonLeafPaths(f.Type, prefix)...)
				continue
			}
			if tag == "" {
				tag = f.Name
			}
			out = append(out, jsonLeafPaths(f.Type, prefix+"."+tag)...)
		}
		return out
	default:
		return []string{prefix}
	}
}

func PreparedInputFieldMap() []PreparedFieldMapping {
	roots := map[string]string{
		"time_series": "hits", "capture_quality": "quality", "dns_records": "inputs[].dns", "dns_lexical_corpus": "inputs[].dns",
		"http_records": "inputs[].http", "brand_registry": "inputs[].http", "network_records": "inputs[].network",
		"verified_connection_outcomes": "inputs[].network", "verified_sessions": "inputs[].network", "bound_connection_hits": "inputs[].network",
		"service_registry": "inputs[].network", "infrastructure_registry": "inputs[].network", "tls_records": "inputs[].tls",
		"tls_trust_and_fingerprint_registry": "inputs[].tls", "history": "inputs[].history", "campaign_and_stage_proofs": "inputs[].history",
		"independent_rule_and_intel_metadata": "inputs[].corroboration", "authorization_records": "inputs[].authorizations",
		"baselines": "inputs[].baselines", "group_membership": "groups", "group_observations": "groups",
	}
	requestPaths := jsonLeafPaths(reflect.TypeOf(evidence.Request{}), "inputs.request")
	scope := []string{"inputs.request.inputs[].scope.asset_id", "inputs.request.inputs[].scope.device_id", "inputs.request.inputs[].scope.endpoint_id", "inputs.request.inputs[].scope.group_id"}
	out := []PreparedFieldMapping{}
	for _, id := range evidence.SupportedFacts() {
		families := evidence.FactInputs(id)
		paths := []string{}
		for _, f := range families {
			root, ok := roots[f]
			if !ok {
				panic("unmapped executable input family: " + f)
			}
			prefix := "inputs.request." + root
			for _, p := range requestPaths {
				if strings.HasPrefix(p, prefix+".") || strings.HasPrefix(p, prefix+"[]") || p == prefix {
					paths = append(paths, p)
				}
			}
		}
		if evidence.AssetWideFact(id) {
			for _, p := range append([]string(nil), paths...) {
				if strings.HasPrefix(p, "inputs.request.inputs[]") {
					paths = append(paths, strings.Replace(p, "inputs.request.inputs[]", "inputs.request.asset_inputs[]", 1))
				}
			}
		}
		if id == "F_HIST_ASSET_IOC_RECURRENCE" || id == "F_HIST_INFRA_PERSISTENCE" {
			paths = append(paths, jsonLeafPaths(reflect.TypeOf(map[string]*evidence.HistoryData{}), "inputs.platform_history")...)
		}
		switch id {
		case evidence.BeaconPeriodic, evidence.MultiDayPersist, "F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW":
			paths = append(paths, jsonLeafPaths(reflect.TypeOf(PhaseOneMaterials{}), "inputs.manifest.phase_one_materials")...)
		}
		paths = uniqueSortedStrings(paths)
		out = append(out, PreparedFieldMapping{string(id), "F", families, paths, scope, "evidence.FactInputs + existing per-rule evaluator; paths list available fields, not unconditional AND prerequisites"})
	}
	for _, s := range evidence.SemanticInputContracts() {
		paths := jsonLeafPaths(reflect.TypeOf(evidence.SemanticMaterial{}), "inputs.semantic_materials.subjects[].materials[]")
		paths = append(paths, jsonLeafPaths(reflect.TypeOf(evidence.Scope{}), "inputs.semantic_materials.subjects[].scope")...)
		out = append(out, PreparedFieldMapping{s.Slot.String(), "S", s.MaterialKinds, paths, []string{"inputs.semantic_materials.subjects[].scope.asset_id", "inputs.semantic_materials.subjects[].scope.device_id", "inputs.semantic_materials.subjects[].scope.endpoint_id", "inputs.semantic_materials.subjects[].scope.group_id"}, "evidence.SemanticInputContracts + semantic prerequisites; F dependencies supplied at runtime"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
