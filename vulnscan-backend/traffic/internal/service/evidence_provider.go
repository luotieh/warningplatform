package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// FieldContract is read from the existing v2.1 input-field-map.json. It is a
// query dependency index, not a second algorithm schema or readiness gate.
type EvidenceFieldContract struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Families []string `json:"input_families"`
	Paths    []string `json:"available_typed_field_paths"`
}
type EvidenceQueryOptions struct {
	// Optional unchanged execution configuration from an existing approved
	// PreparedEvidenceBundle; none of its input data is imported.
	Profile                       *EvidenceExecutionProfile
	Contracts                     []EvidenceFieldContract
	Start, End                    time.Time
	Lookback                      time.Duration
	MaxHits, MaxEvents, MaxAssets int
	MaxBytes                      int64
}
type EvidenceExecutionProfile struct {
	FactConfig      evidence.Config         `json:"fact_config"`
	SemanticOptions ReportSemanticOptions   `json:"semantic_options"`
	JointConfig     evidence.PhaseOneConfig `json:"joint_config"`
}
type EvidenceProviderQuery struct {
	ID        string                  `json:"query_id"`
	Family    string                  `json:"data_family"`
	Rules     []string                `json:"required_by_rules"`
	Keys      any                     `json:"query_keys"`
	Window    evidence.AnalysisWindow `json:"time_window"`
	Provider  string                  `json:"provider"`
	Method    string                  `json:"store_method"`
	Budget    int                     `json:"estimated_budget"`
	Status    string                  `json:"execution_status"`
	Rows      int                     `json:"returned_rows"`
	Coverage  string                  `json:"coverage"`
	Reason    string                  `json:"failure_reason,omitempty"`
	ElapsedMS int64                   `json:"elapsed_ms"`
}
type EvidenceFieldSupply struct {
	Path         string   `json:"field_path"`
	Rules        []string `json:"required_by_rules"`
	Query        string   `json:"query_id"`
	Source       string   `json:"platform_source"`
	SourceIDs    []string `json:"source_ids"`
	Present      bool     `json:"present"`
	Values       []any    `json:"values"`
	Completeness string   `json:"completeness"`
	Reason       string   `json:"missing_reason,omitempty"`
}
type EvidenceSupplyAudit struct {
	Version        string                  `json:"version"`
	EventID        string                  `json:"event_id"`
	ReadOnly       bool                    `json:"read_only"`
	Consistency    string                  `json:"consistency"`
	ContractDigest string                  `json:"contract_sha256"`
	ProfileDigest  string                  `json:"execution_profile_sha256"`
	Queries        []EvidenceProviderQuery `json:"queries"`
	Fields         []EvidenceFieldSupply   `json:"fields"`
	Candidates     []domain.Event          `json:"related_event_candidates"`
	StoredHits     []store.Hit             `json:"stored_hits"`
	Diagnostics    []string                `json:"diagnostics"`
	Valid          bool                    `json:"bundle_valid"`
	ElapsedMS      int64                   `json:"elapsed_ms"`
	Trace          []EvidenceProviderTrace `json:"trace,omitempty"`
	HistoryChecks  []ProviderHistoryCheck  `json:"history_checks,omitempty"`
	CoverageProofs []ProviderCoverageProof `json:"coverage_proofs,omitempty"`
}

func providerOptions(o EvidenceQueryOptions) (EvidenceQueryOptions, error) {
	if o.Lookback == 0 {
		o.Lookback = 30 * 24 * time.Hour
	}
	if o.MaxHits == 0 {
		o.MaxHits = 5000
	}
	if o.MaxEvents == 0 {
		o.MaxEvents = 200
	}
	if o.MaxAssets == 0 {
		o.MaxAssets = 4096
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 16 << 20
	}
	if o.Lookback < 0 || o.Lookback > 90*24*time.Hour || o.MaxHits < 1 || o.MaxHits > 20000 || o.MaxEvents < 1 || o.MaxEvents > 1000 || o.MaxAssets < 1 || o.MaxAssets > 4096 || o.MaxBytes < 1 || o.MaxBytes > 64<<20 {
		return o, fmt.Errorf("provider_budget_invalid")
	}
	seen := map[string]bool{}
	for _, c := range o.Contracts {
		if c.ID == "" || seen[c.ID] {
			return o, fmt.Errorf("provider_contract_duplicate")
		}
		seen[c.ID] = true
	}
	if len(seen) != len(evidence.SupportedFacts())+len(evidence.SemanticDefinitions()) {
		return o, fmt.Errorf("provider_requires_existing_82_contracts")
	}
	for _, id := range evidence.SupportedFacts() {
		if !seen[string(id)] {
			return o, fmt.Errorf("provider_fact_contract_missing")
		}
	}
	for _, d := range evidence.SemanticDefinitions() {
		if !seen[d.Key.String()] {
			return o, fmt.Errorf("provider_semantic_contract_missing")
		}
	}
	return o, nil
}

// PrepareEvidenceFromPlatform is the compatible facade: collect first, then
// preprocess the detached records. Only collection has access to the reader.
func PrepareEvidenceFromPlatform(ctx context.Context, r store.EvidenceReader, id string, options EvidenceQueryOptions) (PreparedEvidenceBundle, EvidenceSupplyAudit, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	collected, err := CollectEvidenceFromPlatform(ctx, r, id, options)
	if err != nil {
		return PreparedEvidenceBundle{}, collected.Audit, err
	}
	return PreprocessCollectedEvidence(ctx, collected)
}

func providerFieldAudit(b PreparedEvidenceBundle, contracts []EvidenceFieldContract) []EvidenceFieldSupply {
	raw, _ := json.Marshal(b)
	var v any
	_ = json.Unmarshal(raw, &v)
	paths := map[string][]string{}
	for _, c := range contracts {
		for _, p := range c.Paths {
			paths[p] = append(paths[p], c.ID)
		}
	}
	keys := []string{}
	for p := range paths {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	out := []EvidenceFieldSupply{}
	for _, p := range keys {
		values := providerPathValues(v, strings.Split(p, "."))
		present := false
		for _, x := range values {
			if x != nil {
				if text, ok := x.(string); !ok || text != "" {
					present = true
				}
			}
		}
		q, source := "Q:traffic", "traffic_event_hits.raw_json/app + explicit deterministic assembly"
		if strings.Contains(p, "history") {
			q, source = "Q:history", "events + existing platform history adapter"
		}
		if strings.Contains(p, "group") {
			q, source = "Q:group", "IOC candidate events + bound saved hits"
		}
		if strings.Contains(p, "baseline") || strings.Contains(p, "authorization") || strings.Contains(p, "brand") {
			q, source = "Q:context", "evidence_sources/active (if configured and scope bound)"
		}
		if strings.HasPrefix(p, "snapshot") || strings.HasPrefix(p, "event") {
			q, source = "Q:event", "events + traffic_aggregation_records(snapshot)"
		}
		if strings.HasPrefix(p, "assets") {
			q, source = "Q:asset", "traffic_assets"
		}
		reason := ""
		if !present {
			reason = "no_bound_saved_field_or_trusted_source; inspect family coverage and algorithm missing reason"
		}
		refs := providerPathSources(v, strings.Split(p, "."), nil)
		if len(refs) == 0 {
			refs = []string{snapshotKey(b.Snapshot.EventID, b.Snapshot.Version)}
		}
		out = append(out, EvidenceFieldSupply{Path: p, Rules: uniqueSortedStrings(paths[p]), Query: q, Source: source, SourceIDs: uniqueSortedStrings(refs), Present: present, Values: values, Completeness: "presence is not readiness; family provenance and algorithm gates remain authoritative", Reason: reason})
	}
	return out
}

func providerPathSources(v any, parts []string, inherited []string) []string {
	m, ok := v.(map[string]any)
	if !ok {
		return inherited
	}
	refs := []string{}
	for _, key := range []string{"source_id", "hit_id"} {
		if id, ok := m[key].(string); ok && id != "" {
			refs = append(refs, id)
		}
	}
	for _, parent := range []map[string]any{m, providerMap(m["provenance"])} {
		if ids, ok := parent["source_ids"].([]any); ok {
			for _, id := range ids {
				if s, ok := id.(string); ok && s != "" {
					refs = append(refs, s)
				}
			}
		}
	}
	if len(refs) > 0 {
		inherited = refs
	}
	if len(parts) == 0 {
		return inherited
	}
	key := strings.TrimSuffix(parts[0], "[]")
	if strings.HasSuffix(parts[0], "[]") {
		out := []string{}
		if xs, ok := m[key].([]any); ok {
			for _, x := range xs {
				out = append(out, providerPathSources(x, parts[1:], inherited)...)
			}
		}
		return out
	}
	return providerPathSources(m[key], parts[1:], inherited)
}
func providerMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func providerQueryRules(contracts []EvidenceFieldContract, family string) []string {
	out := []string{}
	for _, c := range contracts {
		needed := family == "event" || family == "asset"
		for _, f := range c.Families {
			switch family {
			case "traffic":
				needed = needed || !strings.Contains(f, "registry")
			case "history":
				needed = needed || strings.Contains(f, "history") || strings.Contains(f, "time") || strings.Contains(f, "campaign")
			case "group":
				needed = needed || strings.Contains(f, "group") || strings.Contains(f, "current_pattern")
			case "context":
				needed = needed || strings.Contains(f, "registry") || strings.Contains(f, "baseline") || strings.Contains(f, "authorization") || strings.Contains(f, "brand") || strings.Contains(f, "business") || strings.Contains(f, "role") || strings.Contains(f, "metadata") || strings.Contains(f, "corpus")
			}
		}
		if needed {
			out = append(out, c.ID)
		}
	}
	return uniqueSortedStrings(out)
}
func providerPathValues(v any, parts []string) []any {
	if len(parts) == 0 {
		return []any{v}
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	key := strings.TrimSuffix(parts[0], "[]")
	x := m[key]
	if strings.HasSuffix(parts[0], "[]") {
		out := []any{}
		if xs, ok := x.([]any); ok {
			for _, item := range xs {
				out = append(out, providerPathValues(item, parts[1:])...)
			}
		}
		return out
	}
	return providerPathValues(x, parts[1:])
}
