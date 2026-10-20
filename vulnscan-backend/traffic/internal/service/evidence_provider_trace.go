package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Traces carry identities and hashes, never raw request/response bodies.
// SourceIDs bridge stages; TraceID is stable across repeated identical reads.
type EvidenceProviderTrace struct {
	TraceID         string                   `json:"trace_id"`
	EventID         string                   `json:"event_id"`
	SnapshotVersion int64                    `json:"snapshot_version,omitempty"`
	Stage           string                   `json:"stage"`
	Family          string                   `json:"data_family"`
	FieldPath       string                   `json:"field_path"`
	SourceTable     string                   `json:"source_table"`
	SourceIDs       []string                 `json:"input_record_ids"`
	OutputIDs       []string                 `json:"output_record_ids"`
	Scope           evidence.Scope           `json:"scope"`
	Window          *evidence.AnalysisWindow `json:"time_window,omitempty"`
	Transformation  string                   `json:"transformation"`
	Status          string                   `json:"validation_status"`
	RejectReason    string                   `json:"reject_reason,omitempty"`
	Digest          string                   `json:"value_sha256"`
}

type ProviderHistoryCheck struct {
	EventID        string                  `json:"history_event_id"`
	QueryMatch     string                  `json:"query_match_reason"`
	DeviceMatch    bool                    `json:"device_match"`
	AssetMatch     bool                    `json:"asset_match"`
	IOCMatch       bool                    `json:"ioc_match"`
	EndpointMatch  bool                    `json:"endpoint_match"`
	First          time.Time               `json:"event_time"`
	Window         evidence.AnalysisWindow `json:"lookback_window"`
	SourceSnapshot string                  `json:"source_snapshot"`
	SourceQuality  string                  `json:"source_quality"`
	Adjudication   string                  `json:"adjudication"`
	Accepted       bool                    `json:"accepted"`
	Stage          string                  `json:"exclusion_stage"`
	Reasons        []string                `json:"exclusion_reasons"`
}

type ProviderCoverageProof struct {
	WindowCoverageAssumption *PhaseOneTemporalWindowCoverage `json:"window_coverage_assumption,omitempty"`
	AffectedRules            []string                        `json:"affected_rules"`
	Family                   string                          `json:"family"`
	Scope                    evidence.Scope                  `json:"scope"`
	Window                   *evidence.AnalysisWindow        `json:"window"`
	Loaded                   int                             `json:"records_loaded"`
	Declared                 int64                           `json:"records_declared"`
	SnapshotCoverage         bool                            `json:"snapshot_coverage"`
	CollectionCoverage       bool                            `json:"collection_coverage"`
	TransactionCoverage      bool                            `json:"transaction_coverage"`
	Provenance               evidence.Provenance             `json:"provenance"`
	Verified                 bool                            `json:"verified"`
	Complete                 bool                            `json:"complete"`
	Basis                    []string                        `json:"verification_basis"`
	Missing                  []string                        `json:"missing_proofs"`
}

func (a *EvidenceSupplyAudit) trace(stage, family, path, table string, ids []string, scope evidence.Scope, window *evidence.AnalysisWindow, output any, reason string) {
	status := "accepted"
	if reason != "" {
		status = "blocked"
	}
	t := EvidenceProviderTrace{EventID: a.EventID, Stage: stage, Family: family, FieldPath: path, SourceTable: table, SourceIDs: uniqueSortedStrings(ids), Scope: scope, Window: window, Transformation: path, Status: status, RejectReason: reason, Digest: digest(output)}
	sealProviderTrace(&t, 0)
	a.Trace = append(a.Trace, t)
}

func sealProviderTrace(t *EvidenceProviderTrace, version int64) {
	t.SnapshotVersion = version
	t.TraceID, t.OutputIDs = "", nil
	t.TraceID = "T:" + digest(t)
	t.OutputIDs = []string{t.TraceID}
}

type providerTraceReader struct {
	store.EvidenceReader
	audit *EvidenceSupplyAudit
}

func (r *providerTraceReader) EvidenceEvent(ctx context.Context, id string) (domain.Event, bool, error) {
	e, ok, err := r.EvidenceReader.EvidenceEvent(ctx, id)
	r.audit.trace("S1", "event", "EvidenceEvent", "events", []string{id}, evidence.Scope{}, nil, e, readTraceReason(ok, err))
	return e, ok, err
}
func (r *providerTraceReader) EvidenceAssets(ctx context.Context, limit int) ([]domain.Asset, error) {
	rows, err := r.EvidenceReader.EvidenceAssets(ctx, limit)
	ids := []string{}
	for _, a := range rows {
		ids = append(ids, a.ID)
	}
	r.audit.trace("S1", "asset", "EvidenceAssets", "traffic_assets", ids, evidence.Scope{}, nil, rows, readTraceReason(true, err))
	return rows, err
}
func (r *providerTraceReader) AggregateRecord(ctx context.Context, kind, key string) (store.AggregateRecord, bool, error) {
	v, ok, err := r.EvidenceReader.AggregateRecord(ctx, kind, key)
	r.audit.trace("S1", "context", kind+"/"+key, "traffic_aggregation_records", []string{kind + ":" + key}, evidence.Scope{}, nil, v, readTraceReason(ok, err))
	return v, ok, err
}
func (r *providerTraceReader) HistoryCandidates(ctx context.Context, q store.HistoryQuery) ([]domain.Event, error) {
	rows, err := r.EvidenceReader.HistoryCandidates(ctx, q)
	r.audit.trace("S1", "history", "HistoryCandidates.page", "events", nil, evidence.Scope{}, &evidence.AnalysisWindow{Start: q.Start, End: q.End}, struct {
		Query store.HistoryQuery
		Count int
	}{q, len(rows)}, readTraceReason(true, err))
	for _, e := range rows {
		r.audit.trace("S1", "history", "HistoryCandidates", "events", []string{e.EventID}, evidence.Scope{}, &evidence.AnalysisWindow{Start: q.Start, End: q.End}, e, readTraceReason(true, err))
	}
	return rows, err
}
func (r *providerTraceReader) SnapshotPage(ctx context.Context, q store.HitQuery, rw, pb, rb int64) ([]store.Hit, error) {
	rows, err := r.EvidenceReader.SnapshotPage(ctx, q, rw, pb, rb)
	r.audit.trace("S1", "traffic", "SnapshotPage.page", "traffic_event_hits", nil, evidence.Scope{}, &evidence.AnalysisWindow{Start: q.From, End: q.To}, struct {
		Query    store.HitQuery
		Revision int64
		Count    int
	}{q, rw, len(rows)}, readTraceReason(true, err))
	for _, h := range rows {
		r.audit.trace("S1", "traffic", "SnapshotPage", "traffic_event_hits", []string{h.ID}, evidence.Scope{}, &evidence.AnalysisWindow{Start: q.From, End: q.To}, h, readTraceReason(true, err))
		providerTraceSavedFields(r.audit, h, evidence.AnalysisWindow{Start: q.From, End: q.To})
	}
	return rows, err
}

// Record the queried structured value separately from S0 and the mapper. Only
// hashes leave this function. This makes a query projection omission observable
// even when its hit ID and row count survive. No packet or body parser runs.
func providerTraceSavedFields(a *EvidenceSupplyAudit, h store.Hit, w evidence.AnalysisWindow) {
	var raw map[string]any
	if err := json.Unmarshal(h.Raw, &raw); err != nil {
		return
	}
	paths := []string{"request_id", "transaction_id", "session_id", "app.http_url", "app.http_method", "app.user_agent", "app.fields", "app.body_length", "app.truncated", "app.response_status", "app.response_verified", "app.response_location", "app.redirect_to_transaction_id", "app.redirect_verified", "app.form_action", "app.declared_brand", "app.brand_claim_verified", "app.brands", "app.brands_verified", "flow", "exchange", "capture_truncated"}
	for _, path := range paths {
		var v any = raw
		found := true
		for _, part := range strings.Split(path, ".") {
			m, ok := v.(map[string]any)
			if !ok {
				found = false
				break
			}
			v, ok = m[part]
			if !ok {
				found = false
				break
			}
		}
		values, reason := []any{}, ""
		if found {
			values = append(values, v)
		} else {
			reason = "SOURCE_ABSENT_AT_QUERY_RESULT"
		}
		a.trace("S1", "saved_http_field", "saved.raw."+path, "traffic_event_hits", []string{h.ID}, evidence.Scope{}, &w, values, reason)
	}
}
func readTraceReason(ok bool, err error) string {
	if err != nil {
		return "QUERY_FAILED:" + err.Error()
	}
	if !ok {
		return "SOURCE_ABSENT"
	}
	return ""
}

func providerHistoryChecks(history ReportHistory, rows []domain.Event, assets []domain.Asset, devices map[string]bool, sources map[string]CollectedSnapshotReference) ([]ProviderHistoryCheck, error) {
	checks := []ProviderHistoryCheck{}
	accepted := map[string]bool{}
	for _, row := range history.Rows {
		accepted[row.EventID] = true
	}
	for _, e := range rows {
		c := decodeEventContext(e.Context)
		x := ProviderHistoryCheck{EventID: e.EventID, QueryMatch: "broad asset OR IOC candidate; not an exact relation", DeviceMatch: devices[asString(c["device_id"])], Window: evidence.AnalysisWindow{Start: history.Start, End: history.End}, SourceQuality: "saved event metadata; not complete communication coverage", Adjudication: "unreviewed", Accepted: accepted[e.EventID], Reasons: []string{}}
		ids := []string{}
		for _, key := range []string{"src_ip", "dst_ip"} {
			if id, ok := registeredSnapshotAsset(assets, asString(c[key])); ok {
				ids = append(ids, id)
			}
		}
		x.AssetMatch = len(uniqueSortedStrings(ids)) == 1
		for _, ioc := range history.MatchIOCs {
			for _, addr := range history.MatchAddresses {
				if providerHistoryRelation(c, store.HistoryRelation{Address: addr, IOC: ioc}) {
					x.IOCMatch = true
					x.EndpointMatch = true
				}
			}
		}
		first, e1 := time.Parse(time.RFC3339Nano, asString(c["first_time"]))
		last, e2 := time.Parse(time.RFC3339Nano, asString(c["last_time"]))
		x.First = first
		if !x.DeviceMatch {
			x.Reasons = append(x.Reasons, "JOIN_FAILED:device_not_current")
		}
		if !x.AssetMatch {
			x.Reasons = append(x.Reasons, "JOIN_FAILED:registered_asset_not_unique_or_absent")
		}
		if !x.IOCMatch {
			x.Reasons = append(x.Reasons, "JOIN_FAILED:actual_ioc_protocol_field_or_address_missing")
		}
		if e1 != nil || e2 != nil || last.Before(first) || first.Before(history.Start) || !last.Before(history.End) {
			x.Reasons = append(x.Reasons, "JOIN_FAILED:activity_time_outside_lookback_or_invalid")
		}
		source, ok := sources[e.EventID]
		if !ok {
			return checks, fmt.Errorf("collected_history_source_missing:%s", e.EventID)
		}
		if source.Reason != "" {
			x.SourceSnapshot = "unavailable:" + source.Reason
		} else {
			x.SourceSnapshot = snapshotKey(source.Snapshot.EventID, source.Snapshot.Version)
		}

		if !x.Accepted {
			x.Stage = "S2"
		}
		// Snapshot absence is disclosed, not an invented rejection condition:
		// existing history contracts can use bound event-level local positives.
		checks = append(checks, x)
	}
	return checks, nil
}

func providerAssemblyAudit(b PreparedEvidenceBundle, a *EvidenceSupplyAudit) {
	if m := b.Inputs.Manifest.PhaseOne; m != nil {
		refs := []string{}
		for _, contact := range m.Contacts {
			refs = append(refs, contact.HitID)
			a.trace("S2", "contacts", "inputs.manifest.phase_one_materials.contacts", "traffic_event_hits", []string{contact.HitID}, contact.Scope, nil, contact, "")
		}
		a.CoverageProofs = append(a.CoverageProofs, ProviderCoverageProof{AffectedRules: []string{"F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW", "F_MULTI_DAY_PERSIST"}, Family: "contacts", Loaded: len(m.Contacts), Declared: -1, Verified: len(m.Contacts) > 0, Complete: false, Provenance: evidence.Provenance{Verified: len(m.Contacts) > 0, Complete: false, SourceIDs: uniqueSortedStrings(refs), Version: "provider-wire-contacts-1"}, Basis: []string{"validated frame tuple, capture time and actual IOC field; independently deduplicated requests/SYN/DNS questions; frozen per-event watermarks"}, Missing: []string{"COVERAGE_UNPROVEN:independent communication-window coverage; saved row counts are not a network denominator"}})
		proof := &a.CoverageProofs[len(a.CoverageProofs)-1]
		proof.WindowCoverageAssumption = m.TemporalWindowCoverage
		if m.TemporalWindowCoverage != nil {
			proof.Basis = append(proof.Basis, "F_BEACON_JITTER and F_FIXED_DAILY_WINDOW use default_assumption for window coverage; this is not verified capture coverage")
		}
	}
	for _, h := range a.StoredHits {
		found := false
		for _, hit := range b.Inputs.Request.Hits {
			if hit.ID == h.ID {
				found = true
				a.trace("S2", "scope", "snapshotScope", "traffic_event_hits", []string{h.ID}, hit.Scope, nil, hit, "")
				break
			}
		}
		if !found {
			a.trace("S2", "scope", "snapshotScope", "traffic_event_hits", []string{h.ID}, evidence.Scope{}, nil, nil, "SCOPE_INCORRECT:asset_device_endpoint_unresolved")
		}
	}
	for _, x := range a.HistoryChecks {
		a.trace("S2", "history", "history.rows", "events", []string{x.EventID}, evidence.Scope{}, &x.Window, x, strings.Join(x.Reasons, ";"))
	}
	sets := [][]evidence.Input{b.Inputs.Request.Inputs, b.Inputs.Request.AssetInputs}
	for index, set := range sets {
		path := "inputs.request.inputs"
		if index == 1 {
			path = "inputs.request.asset_inputs"
		}
		for _, in := range set {
			if in.Network != nil {
				a.trace("S2", "network", path+".network", "traffic_event_hits", in.Network.SourceIDs, in.Scope, in.Window, in.Network, "")
				providerFamilyProof(b, a, "network", in.Scope, in.Window, in.Network.Provenance, len(in.Network.Connections), false)
			}
			if in.DNS != nil {
				a.trace("S2", "dns", path+".dns", "traffic_event_hits", in.DNS.SourceIDs, in.Scope, in.Window, in.DNS, "")
				providerFamilyProof(b, a, "dns", in.Scope, in.Window, in.DNS.Provenance, len(in.DNS.Records), false)
			}
			if in.HTTP != nil {
				a.trace("S2", "http", path+".http", "traffic_event_hits", in.HTTP.SourceIDs, in.Scope, in.Window, in.HTTP, "")
				providerFamilyProof(b, a, "http", in.Scope, in.Window, in.HTTP.Provenance, len(in.HTTP.Records), false)
			}
		}
	}
	for _, g := range b.Inputs.Request.Groups {
		a.trace("S2", "group", "inputs.request.groups", "traffic_event_hits", g.SourceIDs, evidence.Scope{GroupID: g.ID}, &g.Window, g, "")
		providerFamilyProof(b, a, "group", evidence.Scope{GroupID: g.ID}, &g.Window, g.Provenance, len(g.Connections), false)
	}
	for _, f := range a.Fields {
		reason := ""
		if !f.Present {
			reason = "SOURCE_ABSENT_OR_UNMAPPED:see field-loss-matrix for S0 comparison"
		}
		a.trace("S3", "bundle", f.Path, f.Source, f.SourceIDs, evidence.Scope{}, nil, f.Values, reason)
	}
	for i := range a.Trace {
		sealProviderTrace(&a.Trace[i], b.Snapshot.Version)
	}
}

func providerFamilyProof(b PreparedEvidenceBundle, a *EvidenceSupplyAudit, family string, scope evidence.Scope, w *evidence.AnalysisWindow, p evidence.Provenance, count int, tx bool) {
	snapshotComplete := len(b.Inputs.Manifest.PhaseOne.Sources) > 0
	for _, s := range b.Inputs.Manifest.PhaseOne.Sources {
		snapshotComplete = snapshotComplete && s.Complete
	}
	missing := []string{}
	if !p.Complete {
		missing = append(missing, "COVERAGE_UNPROVEN:full collection population/family denominator")
	}
	if family == "http" && !tx {
		missing = append(missing, "COVERAGE_UNPROVEN:request/response transaction pairing")
	}
	rules := []string{}
	for _, id := range evidence.SupportedFacts() {
		for _, required := range evidence.FactInputs(id) {
			if strings.Contains(required, family) {
				rules = append(rules, string(id))
				break
			}
		}
	}
	a.CoverageProofs = append(a.CoverageProofs, ProviderCoverageProof{AffectedRules: rules, Family: family, Scope: scope, Window: w, Loaded: count, Declared: -1, SnapshotCoverage: snapshotComplete, CollectionCoverage: p.Complete, TransactionCoverage: tx, Provenance: p, Verified: p.Verified, Complete: p.Complete, Basis: []string{"per-snapshot loaded/count equality is separate from unknown family denominator (-1); published watermarks and saved hit IDs do not prove full-network coverage"}, Missing: missing})
}

// ProviderExecutionTrace records original engine results separately from
// normalization; no static dependency guess changes their authoritative state.
func ProviderExecutionTrace(b PreparedEvidenceBundle, out PreparedEvidenceExecution) []EvidenceProviderTrace {
	a := EvidenceSupplyAudit{EventID: b.Event.EventID}
	if out.Evaluation.Result != nil {
		for _, f := range out.Evaluation.Result.Findings {
			reason := ""
			if f.Status == evidence.Missing {
				reason = string(f.ReasonCode)
			}
			a.trace("S4", "fact", string(f.FactID), "existing F engine", f.SourceIDs, f.Scope, nil, f, reason)
		}
	}
	if out.Semantics.Result != nil {
		a.trace("S4", "semantic", "semantic.plan/results", "existing S engine", nil, evidence.Scope{}, nil, out.Semantics.Result, "")
	}
	for _, x := range out.Evidence.Normalized.Items {
		reason := ""
		if x.TerminalStatus == "missing" || x.TerminalStatus == "execution_error" {
			reason = x.Reason
		}
		a.trace("S5", x.Kind, x.RuleID, "existing normalizer", x.SourceIDs, x.Scope, nil, x, reason)
	}
	for i := range a.Trace {
		sealProviderTrace(&a.Trace[i], b.Snapshot.Version)
	}
	return a.Trace
}

// Keep raw store objects internal for group budgets. Public audit values are
// hashes; Bundle remains the explicit, access-controlled local evidence file.
func ProviderRedactedAudit(a EvidenceSupplyAudit) EvidenceSupplyAudit {
	a.StoredHits = nil
	a.Candidates = nil
	a.Fields = append([]EvidenceFieldSupply(nil), a.Fields...)
	for i := range a.Fields {
		raw, _ := json.Marshal(a.Fields[i].Values)
		a.Fields[i].Values = []any{map[string]any{"sha256": digest(a.Fields[i].Values), "serialized_bytes": len(raw), "redacted": true}}
	}
	return a
}
