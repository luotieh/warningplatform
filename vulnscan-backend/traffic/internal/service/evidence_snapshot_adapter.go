package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

const snapshotAdapterVersion = "snapshot-evidence-adapter-0.4"

// SnapshotEvidenceOptions limits the shared load, not each algorithm separately.
// Large snapshots are explicitly deferred, never evaluated using model samples.
type SnapshotEvidenceOptions struct {
	CaptureSemantic   bool
	Facts             []evidence.FactID
	MaxHits           int64
	MaxRawBytes       int64
	MaxScopes         int
	Supplemental      *SnapshotSupplementalInputs `json:"-"`
	SupplementalIssue *SnapshotInputIssue         `json:"-"`
	Sources           *EvidenceSourceRegistry     `json:"-"`
	SourceIssue       *SnapshotInputIssue         `json:"-"`
	RegistryIssue     *SnapshotInputIssue         `json:"-"`
}

func DefaultSnapshotEvidenceOptions() SnapshotEvidenceOptions {
	return SnapshotEvidenceOptions{MaxHits: 20000, MaxRawBytes: 16 << 20, MaxScopes: 256}
}

type SnapshotEvidenceManifest struct {
	AdapterVersion        string                 `json:"adapter_version"`
	RegistryVersion       string                 `json:"registry_version"`
	SnapshotVersion       int64                  `json:"snapshot_version"`
	Watermark             int64                  `json:"watermark"`
	RevisionWatermark     int64                  `json:"revision_watermark"`
	DeclaredHits          int64                  `json:"declared_hits"`
	LoadedHits            int64                  `json:"loaded_hits"`
	BoundHits             int64                  `json:"bound_hits"`
	UnresolvedHits        int64                  `json:"unresolved_hits"`
	ReadPages             int                    `json:"read_pages"`
	RevisionBatches       int                    `json:"revision_batches"`
	RawBytes              int64                  `json:"raw_bytes"`
	MaxHits               int64                  `json:"max_hits"`
	MaxRawBytes           int64                  `json:"max_raw_bytes"`
	MaxScopes             int                    `json:"max_scopes"`
	Coverage              string                 `json:"coverage"`
	MissingInputs         []string               `json:"missing_inputs"`
	Issues                []SnapshotInputIssue   `json:"issues,omitempty"`
	IssueCount            int                    `json:"issue_count"`
	OmittedIssues         int                    `json:"omitted_issues"`
	FactCoverage          []SnapshotFactCoverage `json:"fact_coverage,omitempty"`
	SupplementalVersion   string                 `json:"supplemental_version,omitempty"`
	SourceRegistryVersion string                 `json:"source_registry_version,omitempty"`
}

type SnapshotEvidenceInput struct {
	Request              evidence.Request              `json:"-"`
	SemanticObservations []SnapshotSemanticObservation `json:"-"`
	Manifest             SnapshotEvidenceManifest      `json:"manifest"`
	Reason               string                        `json:"reason,omitempty"`
}

type SnapshotFactEvaluation struct {
	Status   string                   `json:"status"`
	Reason   string                   `json:"reason,omitempty"`
	Manifest SnapshotEvidenceManifest `json:"manifest"`
	Result   *evidence.Result         `json:"result,omitempty"`
	CacheHit bool                     `json:"cache_hit"`
}

// snapshotHitPage shares one membership/revision query per page. No algorithm
// queries a hit, and revisions newer than the snapshot can never leak in.
func snapshotHitPage(ctx context.Context, st store.Store, q store.HitQuery, revisionWatermark int64) ([]store.Hit, error) {
	page, err := st.HitPage(ctx, q)
	if err != nil || len(page) == 0 || revisionWatermark <= 0 {
		return page, err
	}
	ids := make([]string, len(page))
	for i, h := range page {
		ids[i] = h.ID
	}
	revisions, err := st.HitRevisions(ctx, ids, revisionWatermark)
	if err != nil {
		return nil, err
	}
	for i := range page {
		if raw, ok := revisions[page[i].ID]; ok {
			page[i].Raw = raw
		}
	}
	return page, nil
}

// SnapshotEvidenceInput uses the caller's already loaded immutable snapshot.
// Only committed hit records are read. assets must come from the server registry;
// raw payloads, model labels, IOC matches and client verified flags are not proofs.
func (s Services) SnapshotEvidenceInput(ctx context.Context, snap EvidenceSnapshot, assets []domain.Asset, opts SnapshotEvidenceOptions) (out SnapshotEvidenceInput, err error) {
	out = SnapshotEvidenceInput{Manifest: SnapshotEvidenceManifest{
		AdapterVersion: snapshotAdapterVersion, SnapshotVersion: snap.Version,
		RegistryVersion: snapshotRegistryVersion(assets),
		Watermark:       snap.Watermark, RevisionWatermark: snap.RevisionWatermark,
		DeclaredHits: snap.Count, MaxHits: opts.MaxHits, MaxRawBytes: opts.MaxRawBytes,
		Coverage: "unknown", MissingInputs: []string{"baselines", "history", "campaign_and_stage_proofs", "group_membership", "authorization_records", "tls_trust_and_fingerprint_registry", "independent_rule_and_intel_metadata", "brand_registry", "service_registry", "dns_lexical_corpus", "infrastructure_registry"},
	}}
	if opts.MaxScopes == 0 {
		opts.MaxScopes = 256
	}
	out.Manifest.MaxScopes = opts.MaxScopes
	defer func() {
		if err == nil && out.Reason != "" {
			out.Manifest.addIssue(SnapshotInputIssue{Code: out.Reason, Stage: "load"})
		}
		if err != nil {
			out.Request.Hits, out.Request.Inputs = nil, nil
			code, stage := "input_validation_failed", "validate"
			var failure *SnapshotInputError
			if errors.As(err, &failure) {
				code, stage = failure.Code, failure.Stage
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				code, stage = "input_cancelled", "load"
			}
			out.Reason = code
			out.Manifest.addIssue(snapshotIssueCause(SnapshotInputIssue{Code: code, Stage: stage, Retryable: code == "snapshot_read_failed"}, err))
			hitID := ""
			if failure != nil {
				hitID = failure.HitID
			}
			err = &SnapshotInputError{Code: code, Stage: stage, EventID: snap.EventID, SnapshotVersion: snap.Version, HitID: hitID, Cause: err}
		}
	}()
	if opts.SupplementalIssue != nil {
		out.Manifest.addIssue(*opts.SupplementalIssue)
	}
	if opts.SourceIssue != nil {
		out.Manifest.addIssue(*opts.SourceIssue)
	}
	if opts.RegistryIssue != nil {
		out.Manifest.addIssue(*opts.RegistryIssue)
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if snap.EventID == "" || snap.Version <= 0 || snap.Watermark <= 0 || snap.Count < 1 || len(snap.Sources) == 0 {
		return out, &SnapshotInputError{Code: "snapshot_identity_invalid", Stage: "validate_snapshot", Cause: errors.New("invalid snapshot identity")}
	}
	if opts.MaxHits < 1 || opts.MaxRawBytes < 1 || opts.MaxScopes < 1 {
		return out, errors.New("positive snapshot input budgets required")
	}
	// Validate selection even when binding/data budgets prevent evaluation.
	known := map[evidence.FactID]bool{}
	for _, id := range evidence.SupportedFacts() {
		known[id] = true
	}
	seen := map[evidence.FactID]bool{}
	for _, id := range opts.Facts {
		if !known[id] || seen[id] {
			return out, fmt.Errorf("unknown or duplicate evidence fact %q", id)
		}
		seen[id] = true
	}
	out.Request = evidence.Request{EventID: snap.EventID, SnapshotVersion: snap.Version, Facts: opts.Facts, Hits: []evidence.Hit{}, Inputs: []evidence.Input{}}
	if opts.Facts != nil && len(opts.Facts) == 0 {
		out.Reason = "not_requested"
		return out, nil
	}
	if snap.Count > opts.MaxHits {
		out.Reason = "snapshot_hit_budget_exceeded"
		return out, nil
	}
	if !hasRegistryIdentity(assets) {
		out.Reason = "asset_registry_unavailable"
		return out, nil
	}
	inputs := map[evidence.Scope]*evidence.Input{}
	counts := map[evidence.Scope]int{}
	scopeHits := map[evidence.Scope][]evidence.Hit{}
	seenHits := map[string]bool{}
	allCaptureKnown, anyTruncated := true, false
	q := store.HitQuery{Sources: snap.Sources, Watermark: snap.Watermark, Limit: 500}
	for {
		page, err := snapshotHitPage(ctx, s.Store, q, snap.RevisionWatermark)
		if err != nil {
			return out, &SnapshotInputError{Code: "snapshot_read_failed", Stage: "load_hits_and_revisions", Cause: err}
		}
		out.Manifest.ReadPages++
		if len(page) == 0 {
			break
		}
		if snap.RevisionWatermark > 0 {
			out.Manifest.RevisionBatches++
		}
		for _, h := range page {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if h.ID == "" || seenHits[h.ID] {
				return out, &SnapshotInputError{Code: "duplicate_or_empty_hit_identity", Stage: "validate_hits", HitID: h.ID, Cause: errors.New("invalid hit identity")}
			}
			seenHits[h.ID] = true
			out.Manifest.LoadedHits++
			out.Manifest.RawBytes += int64(len(h.Raw))
			if out.Manifest.LoadedHits > opts.MaxHits || out.Manifest.RawBytes > opts.MaxRawBytes {
				out.Request.Hits, out.Request.Inputs = nil, nil
				out.Reason = "snapshot_input_budget_exceeded"
				return out, nil
			}
			m := map[string]any{}
			decoder := json.NewDecoder(bytes.NewReader(h.Raw))
			decoder.UseNumber()
			if err := decoder.Decode(&m); err != nil {
				out.Manifest.addIssue(SnapshotInputIssue{Code: "stored_json_invalid", Stage: "decode", HitID: h.ID, Field: "raw_json"})
				return out, &SnapshotInputError{Code: "stored_json_invalid", Stage: "decode", HitID: h.ID, Cause: err}
			}
			var trailing any
			if decodeErr := decoder.Decode(&trailing); decodeErr != io.EOF {
				return out, &SnapshotInputError{Code: "stored_json_invalid", Stage: "decode", HitID: h.ID, Cause: errors.New("trailing stored JSON")}
			}
			scope, remoteIP, remotePort, ok := snapshotScope(m, assets)
			if !ok || h.OccurredAt.IsZero() {
				out.Manifest.UnresolvedHits++
				out.Manifest.addIssue(SnapshotInputIssue{Code: "unresolved_binding_or_time", Stage: "bind", HitID: h.ID, Field: "asset/endpoint/device/time"})
				continue
			}
			truncated, known := nestedMap(m, "raw_packet")["capture_truncated"].(bool)
			if !known {
				allCaptureKnown = false
				out.Manifest.addIssue(SnapshotInputIssue{Code: "field_missing", Stage: "quality", HitID: h.ID, Scope: scope, Field: "raw_packet.capture_truncated"})
			}
			anyTruncated = anyTruncated || truncated
			hit := evidence.Hit{ID: h.ID, OccurredAt: h.OccurredAt, Scope: scope}
			if n, ok := strictUint(m["packets"]); ok {
				hit.Packets = &n
			} else {
				out.Manifest.addIssue(SnapshotInputIssue{Code: "field_missing_or_invalid", Stage: "parse", HitID: h.ID, Scope: scope, Field: "packets"})
			}
			out.Request.Hits = append(out.Request.Hits, hit)
			out.Manifest.BoundHits++
			input := inputs[scope]
			if input == nil {
				if len(inputs) >= opts.MaxScopes {
					out.Request.Hits, out.Request.Inputs = nil, nil
					out.Reason = "snapshot_scope_budget_exceeded"
					return out, nil
				}
				input = &evidence.Input{Scope: scope}
				inputs[scope] = input
			}
			counts[scope]++
			scopeHits[scope] = append(scopeHits[scope], hit)
			adaptSnapshotProtocols(input, h, m, remoteIP, remotePort, known && !truncated)
			enrichSnapshotProtocols(input, h, m, &out.Manifest)
			if opts.CaptureSemantic {
				collectSnapshotSemanticObservation(&out, input, h, m, assets)
			}
		}
		tail := page[len(page)-1]
		if !q.AfterTime.IsZero() && (tail.OccurredAt.Before(q.AfterTime) || (tail.OccurredAt.Equal(q.AfterTime) && tail.ID <= q.AfterID)) {
			return out, &SnapshotInputError{Code: "snapshot_cursor_stalled", Stage: "pagination", HitID: tail.ID, Cause: errors.New("cursor did not advance")}
		}
		q.AfterTime, q.AfterID = tail.OccurredAt, tail.ID
	}
	if out.Manifest.LoadedHits != snap.Count {
		return out, &SnapshotInputError{Code: "snapshot_membership_mismatch", Stage: "validate_membership", Cause: fmt.Errorf("expected %d loaded %d", snap.Count, out.Manifest.LoadedHits)}
	}
	if len(out.Request.Hits) == 0 {
		out.Reason = "unresolved_asset_endpoint_binding"
		return out, nil
	}
	coverage := evidence.CoverageComplete
	if out.Manifest.UnresolvedHits > 0 {
		coverage = evidence.CoveragePartial
	}
	out.Request.Quality.Coverage = coverage
	if allCaptureKnown || anyTruncated {
		out.Request.Quality.CaptureTruncated = &anyTruncated
	}
	out.Manifest.Coverage = string(coverage)
	for scope, input := range inputs {
		refs := []string{}
		var first, last time.Time
		for _, hit := range scopeHits[scope] {
			refs = append(refs, hit.ID)
			if first.IsZero() || hit.OccurredAt.Before(first) {
				first = hit.OccurredAt
			}
			if last.IsZero() || hit.OccurredAt.After(last) {
				last = hit.OccurredAt
			}
		}
		input.Window = &evidence.AnalysisWindow{Start: first, End: last.Add(time.Nanosecond)}
		provenance := evidence.Provenance{Verified: true, Complete: coverage == evidence.CoverageComplete, Version: fmt.Sprintf("%s:%d:%d:%d", snap.EventID, snap.Version, snap.Watermark, snap.RevisionWatermark), SourceIDs: refs}
		if input.Network != nil {
			input.Network.Provenance = provenance
		}
		if input.HTTP != nil {
			input.HTTP.Provenance = provenance
			input.HTTP.Complete = provenance.Complete && len(input.HTTP.Records) == counts[scope]
		}
		if input.DNS != nil {
			input.DNS.Provenance = provenance
			input.DNS.Complete = provenance.Complete && len(input.DNS.Records) == counts[scope]
		}
		if input.TLS != nil {
			input.TLS.Provenance = provenance
			input.TLS.Complete = false
		}
		out.Request.Inputs = append(out.Request.Inputs, *input)
	}
	sort.Slice(out.Request.Inputs, func(i, j int) bool {
		return scopeKey(out.Request.Inputs[i].Scope) < scopeKey(out.Request.Inputs[j].Scope)
	})
	buildSnapshotAssetInputs(&out.Request)
	produceSnapshotSupplemental(&out, snap, opts.Sources)
	applySnapshotSupplemental(&out, snap, opts.Supplemental)
	return out, nil
}

func scopeKey(s evidence.Scope) string {
	return s.AssetID + "\x00" + s.EndpointID + "\x00" + s.DeviceID
}

func hasRegistryIdentity(assets []domain.Asset) bool {
	for _, a := range assets {
		if a.ID != "" && a.Status == 1 && strings.TrimSpace(a.Address) != "" {
			return true
		}
	}
	return false
}

func snapshotRegistryVersion(assets []domain.Asset) string {
	ordered := append([]domain.Asset(nil), assets...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	return digest(ordered)
}

// Prefer a unique exact registry entry. CIDRs identify coverage, not a single
// machine: append the actual IP so two hosts in one registered subnet stay apart.
func registeredSnapshotAsset(assets []domain.Asset, raw string) (string, bool) {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return "", false
	}
	ip = ip.Unmap()
	bestBits := -1
	identities := map[string]bool{}
	for _, a := range assets {
		if a.ID == "" || a.Status != 1 {
			continue
		}
		bits := -1
		identity := a.ID
		if addr, err := netip.ParseAddr(strings.TrimSpace(a.Address)); err == nil && addr.Unmap() == ip {
			bits = 129
		} else if prefix, err := netip.ParsePrefix(strings.TrimSpace(a.Address)); err == nil && prefix.Contains(ip) {
			bits = prefix.Bits()
			identity += "@" + ip.String()
		}
		if bits < 0 || bits < bestBits {
			continue
		}
		if bits > bestBits {
			bestBits = bits
			identities = map[string]bool{}
		}
		identities[identity] = true
	}
	if len(identities) != 1 {
		return "", false
	}
	for id := range identities {
		return id, true
	}
	return "", false
}

func snapshotScope(m map[string]any, assets []domain.Asset) (evidence.Scope, string, uint16, bool) {
	device := strings.TrimSpace(asString(m["device_id"]))
	src, dst := asString(m["src_ip"]), asString(m["dst_ip"])
	srcID, srcOK := registeredSnapshotAsset(assets, src)
	dstID, dstOK := registeredSnapshotAsset(assets, dst)
	// Both registered (including lateral/DNS infrastructure) needs independent
	// ownership/direction proof; neither IOC nor victim_target can supply it.
	if device == "" || srcOK == dstOK {
		return evidence.Scope{}, "", 0, false
	}
	asset, remote, port := srcID, dst, m["dst_port"]
	if dstOK {
		asset, remote, port = dstID, src, m["src_port"]
	}
	ip, err := netip.ParseAddr(remote)
	n, ok := strictUint(port)
	protocol := strings.ToLower(firstNonEmpty(asString(m["protocol"]), asString(m["proto"])))
	if err != nil || !ok || n == 0 || n > 65535 || (protocol != "tcp" && protocol != "udp") {
		return evidence.Scope{}, "", 0, false
	}
	remote = ip.Unmap().String()
	return evidence.Scope{AssetID: asset, EndpointID: protocol + "://" + net.JoinHostPort(remote, strconv.FormatUint(n, 10)), DeviceID: device}, remote, uint16(n), true
}

func strictUint(v any) (uint64, bool) {
	var raw string
	switch n := v.(type) {
	case json.Number:
		raw = string(n)
	case string:
		raw = n
	case uint64:
		return n, true
	case int:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case int64:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	default:
		return 0, false
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	return n, err == nil
}

func adaptSnapshotProtocols(input *evidence.Input, h store.Hit, m map[string]any, remote string, port uint16, fullCapture bool) {
	app := nestedMap(m, "app")
	if input.Network == nil {
		input.Network = &evidence.NetworkData{}
	}
	connection := evidence.Connection{SourceID: h.ID, Time: h.OccurredAt, AssetID: input.Scope.AssetID, Destination: remote, Port: port, SessionID: asString(m["session_id"])}
	// Flow counters are cumulative; do not label them as payload size per packet.
	if fullCapture {
		rp := nestedMap(m, "raw_packet")
		if hex, ok := rp["payload_hex"].(string); ok && len(hex)%2 == 0 {
			if decoded, err := decodeSnapshotPayloadHex(hex); err == nil {
				size := uint64(len(decoded))
				connection.PayloadBytes = &size
			}
		}
	}
	input.Network.Connections = append(input.Network.Connections, connection)
	if domain := strings.TrimSpace(asString(app["dns_query"])); domain != "" {
		if input.DNS == nil {
			input.DNS = &evidence.DNSData{}
		}
		record := evidence.DNSRecord{SourceID: h.ID, Time: h.OccurredAt, Domain: domain}
		if rcode, ok := strictUint(app["dns_rcode"]); ok && rcode <= 15 {
			record.RCode = int(rcode)
			record.RCodeKnown = true
		}
		if answers, ok := app["dns_answers"].([]any); ok {
			for _, v := range answers {
				if a, ok := v.(string); ok {
					record.Answers = append(record.Answers, a)
				}
			}
		}
		input.DNS.Records = append(input.DNS.Records, record)
	}
	if rawURL := snapshotHTTPURL(app, nestedMap(m, "raw_packet")); rawURL != "" {
		parsed, err := url.Parse(rawURL)
		if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != "" {
			if input.HTTP == nil {
				input.HTTP = &evidence.HTTPData{}
			}
			// app body fields are samples. They cannot establish full credential
			// fields, lengths, decoding chains or response/redirect verification.
			record := evidence.HTTPRecord{SourceID: h.ID, Time: h.OccurredAt, URL: rawURL, Method: asString(app["http_method"]), UserAgent: asString(app["user_agent"]), TransactionID: asString(m["transaction_id"]), SessionID: asString(m["session_id"]), Truncated: true}
			input.HTTP.Records = append(input.HTTP.Records, record)
		}
	}
}

// The push contract's http_url is often just a path. Do not invent a scheme
// from port 443/80 or Host. A parsed cleartext HTTP request can supply it.
func snapshotHTTPURL(app, packet map[string]any) string {
	raw := asString(app["http_url"])
	if parsed, err := url.Parse(raw); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != "" {
		return raw
	}
	request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(asString(packet["payload_text"]))))
	if err != nil {
		return ""
	}
	if request.Body != nil {
		defer request.Body.Close()
	}
	if method := asString(app["http_method"]); method != "" && method != request.Method {
		return ""
	}
	if raw != "" && raw != request.RequestURI {
		return ""
	}
	if host := asString(app["http_host"]); host != "" && !strings.EqualFold(host, request.Host) {
		return ""
	}
	if request.URL.IsAbs() {
		return request.URL.String()
	}
	if request.Host == "" {
		return ""
	}
	copy := *request.URL
	copy.Scheme = "http"
	copy.Host = request.Host
	if copy.Hostname() == "" {
		return ""
	}
	return copy.String()
}

func decodeSnapshotPayloadHex(raw string) ([]byte, error) { return hex.DecodeString(raw) }

func (s Services) EvaluateSnapshotFacts(ctx context.Context, snap EvidenceSnapshot, assets []domain.Asset, opts SnapshotEvidenceOptions, cfg evidence.Config) (SnapshotFactEvaluation, error) {
	input, err := s.SnapshotEvidenceInput(ctx, snap, assets, opts)
	return evaluateSnapshotFactInput(ctx, snap, input, err, opts, cfg)
}

func evaluateSnapshotFactInput(ctx context.Context, snap EvidenceSnapshot, input SnapshotEvidenceInput, inputErr error, opts SnapshotEvidenceOptions, cfg evidence.Config) (SnapshotFactEvaluation, error) {
	if opts.Supplemental != nil && validateSnapshotSupplemental(snap, *opts.Supplemental) == nil && opts.Supplemental.Policies != nil {
		cfg.Policies = opts.Supplemental.Policies
	}
	engine, err := evidence.NewEngine(cfg)
	if err != nil {
		return SnapshotFactEvaluation{}, err
	}
	err = inputErr
	out := SnapshotFactEvaluation{Status: "unavailable", Reason: input.Reason, Manifest: input.Manifest}
	out.Manifest.FactCoverage = snapshotUnavailableCoverage(opts.Facts, evidence.ReasonCode(out.Reason))
	if err != nil {
		return out, err
	}
	if input.Reason != "" {
		return out, nil
	}
	result, err := engine.Evaluate(ctx, input.Request)
	if err != nil {
		out.Reason = "algorithm_input_invalid"
		out.Manifest.addIssue(SnapshotInputIssue{Code: out.Reason, Stage: "evaluate"})
		out.Manifest.FactCoverage = snapshotUnavailableCoverage(opts.Facts, evidence.ReasonCode(out.Reason))
		return out, &SnapshotInputError{Code: out.Reason, Stage: "evaluate", EventID: snap.EventID, SnapshotVersion: snap.Version, Cause: err}
	}
	for i := range result.Findings {
		result.Findings[i].Dependencies = append(result.Findings[i].Dependencies,
			evidence.Dependency{Kind: "asset_registry", Version: input.Manifest.RegistryVersion},
			evidence.Dependency{Kind: "hit_snapshot", Version: fmt.Sprintf("%s:%d:%d:%d", snap.EventID, snap.Version, snap.Watermark, snap.RevisionWatermark), SourceIDs: append([]string(nil), snap.Sources...)})
		if input.Manifest.SupplementalVersion != "" {
			result.Findings[i].Dependencies = append(result.Findings[i].Dependencies, evidence.Dependency{Kind: "supplemental_inputs", Version: input.Manifest.SupplementalVersion, SourceIDs: []string{snapshotKey(snap.EventID, snap.Version)}})
		}
		if input.Manifest.SourceRegistryVersion != "" {
			result.Findings[i].Dependencies = append(result.Findings[i].Dependencies, evidence.Dependency{Kind: "trusted_source_registry", Version: input.Manifest.SourceRegistryVersion, SourceIDs: []string{input.Manifest.SourceRegistryVersion}})
		}
	}
	out.Status = "evaluated"
	out.Result = &result
	out.Manifest.FactCoverage = snapshotFactCoverage(input.Request, result)
	return out, nil
}
