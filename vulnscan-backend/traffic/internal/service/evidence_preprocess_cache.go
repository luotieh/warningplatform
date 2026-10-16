package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

const evidencePreprocessVersion = "evidence-preprocess-2.1"
const preprocessCacheBytes = 8 << 20
const preprocessDecodedBytes = 64 << 20

// Raw HTTP fields intentionally do not serialize in public evidence.Request.
// This private journal envelope preserves them for later semantic planning.
type PreparedHTTPPayload struct {
	Raw  string `json:"raw"`
	Body string `json:"body"`
}

// EvidencePreparedInputs is the lossless, serializable L2 input collection.
// Request holds the existing DNS/HTTP/TLS/network/history/group input families;
// HTTP and PlatformHistory preserve fields excluded from public report JSON.
type EvidencePreparedInputs struct {
	SemanticMaterials *evidence.SemanticRequest        `json:"semantic_materials"`
	Request           evidence.Request                 `json:"request"`
	Manifest          SnapshotEvidenceManifest         `json:"manifest"`
	Observations      []SnapshotSemanticObservation    `json:"observations"`
	HTTP              map[string]PreparedHTTPPayload   `json:"http"`
	PlatformHistory   map[string]*evidence.HistoryData `json:"platform_history"`
	Reason            string                           `json:"reason,omitempty"`
}
type preprocessedEnvelope struct {
	Version string `json:"version"`
	Key     string `json:"key"`
	SHA256  string `json:"sha256"`
	Data    []byte `json:"gzip"`
}

func encodePreprocessed(input SnapshotEvidenceInput, key string) (preprocessedEnvelope, error) {
	value := capturePreparedInputs(input)
	raw, err := json.Marshal(value)
	if err != nil {
		return preprocessedEnvelope{}, err
	}
	if len(raw) > preprocessDecodedBytes {
		return preprocessedEnvelope{}, io.ErrShortBuffer
	}
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err = w.Write(raw); err != nil {
		return preprocessedEnvelope{}, err
	}
	if err = w.Close(); err != nil {
		return preprocessedEnvelope{}, err
	}
	if compressed.Len() > preprocessCacheBytes {
		return preprocessedEnvelope{}, io.ErrShortBuffer
	}
	return preprocessedEnvelope{Version: evidencePreprocessVersion, Key: key, SHA256: digest(raw), Data: compressed.Bytes()}, nil
}

func capturePreparedInputs(input SnapshotEvidenceInput) EvidencePreparedInputs {
	value := EvidencePreparedInputs{SemanticMaterials: input.PreparedSemantics, Request: input.Request, Manifest: input.Manifest, Observations: input.SemanticObservations, HTTP: map[string]PreparedHTTPPayload{}, PlatformHistory: map[string]*evidence.HistoryData{}, Reason: input.Reason}
	for _, inputs := range [][]evidence.Input{input.Request.Inputs, input.Request.AssetInputs} {
		for _, in := range inputs {
			value.PlatformHistory[scopeKey(in.Scope)] = in.PlatformHistory
			if in.HTTP != nil {
				for _, r := range in.HTTP.Records {
					value.HTTP[r.SourceID] = PreparedHTTPPayload{r.RawRequest, r.ParsedBody}
				}
			}
		}
	}
	for _, o := range input.SemanticObservations {
		if h := o.HTTP; h != nil {
			value.HTTP[h.SourceID] = PreparedHTTPPayload{h.RawRequest, h.ParsedBody}
		}
	}
	return value
}

func decodePreprocessed(envelope preprocessedEnvelope, key string, snap EvidenceSnapshot) (SnapshotEvidenceInput, bool) {
	if envelope.Version != evidencePreprocessVersion || envelope.Key != key || len(envelope.Data) > preprocessCacheBytes {
		return SnapshotEvidenceInput{}, false
	}
	r, err := gzip.NewReader(bytes.NewReader(envelope.Data))
	if err != nil {
		return SnapshotEvidenceInput{}, false
	}
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, preprocessDecodedBytes+1))
	if err != nil || len(raw) > preprocessDecodedBytes || digest(raw) != envelope.SHA256 {
		return SnapshotEvidenceInput{}, false
	}
	var value EvidencePreparedInputs
	if json.Unmarshal(raw, &value) != nil || value.Request.EventID != snap.EventID || value.Request.SnapshotVersion != snap.Version || value.Manifest.Watermark != snap.Watermark || value.Manifest.RevisionWatermark != snap.RevisionWatermark || value.Manifest.AdapterVersion != reportSnapshotAdapterVersion {
		return SnapshotEvidenceInput{}, false
	}
	return restorePreparedInputs(value), true
}

func restorePreparedInputs(value EvidencePreparedInputs) SnapshotEvidenceInput {
	for _, inputs := range [][]evidence.Input{value.Request.Inputs, value.Request.AssetInputs} {
		for n := range inputs {
			in := &inputs[n]
			in.PlatformHistory = value.PlatformHistory[scopeKey(in.Scope)]
			if in.HTTP != nil {
				for i := range in.HTTP.Records {
					r := &in.HTTP.Records[i]
					saved := value.HTTP[r.SourceID]
					r.RawRequest, r.ParsedBody = saved.Raw, saved.Body
				}
			}
		}
	}
	for n := range value.Observations {
		if h := value.Observations[n].HTTP; h != nil {
			saved := value.HTTP[h.SourceID]
			h.RawRequest, h.ParsedBody = saved.Raw, saved.Body
		}
	}
	if m := value.Manifest.PhaseOne; m != nil {
		for i := range m.Records {
			if h := m.Records[i].HTTP; h != nil {
				h.RawRequest, h.ParsedBody = m.Records[i].RawRequest, m.Records[i].ParsedBody
			}
		}
	}
	return SnapshotEvidenceInput{PreparedSemantics: value.SemanticMaterials, Request: value.Request, Manifest: value.Manifest, SemanticObservations: value.Observations, Reason: value.Reason}
}

// Model identity, prompt, F thresholds and C scoring are absent from this key.
// Mutable source/asset/history versions still invalidate the prepared features.
func (s Services) pipelinePreprocessed(ctx context.Context, snap EvidenceSnapshot, assets []domain.Asset, opts SnapshotEvidenceOptions, persist bool) (SnapshotEvidenceInput, error) {
	defer pipelineMeasure(ctx, "preprocess")()
	identity := opts
	identity.Facts = nil
	identity.DeferIndependentFacts = false
	key := digest([]any{evidencePreprocessVersion, reportSnapshotAdapterVersion, snap.EventID, snap.Version, snap.Watermark, snap.RevisionWatermark, identity, assets, opts.Supplemental, opts.Sources, opts.RegistryIssue, opts.SourceIssue, opts.SupplementalIssue})
	cacheable := opts.RegistryIssue == nil && opts.SourceIssue == nil && opts.SupplementalIssue == nil
	if cacheable {
		if record, ok, err := s.Store.AggregateRecord(ctx, "evidence_preprocess", key); err == nil && ok && len(record.Value) <= 12<<20 {
			var saved preprocessedEnvelope
			if json.Unmarshal(record.Value, &saved) == nil {
				if input, valid := decodePreprocessed(saved, key, snap); valid {
					input.Request.Facts = opts.Facts
					input.Manifest.PreprocessCacheHit = true
					if m := pipelineMetrics(ctx); m != nil {
						m.CacheHits["preprocess"]++
					}
					return input, nil
				}
			}
		}
	}
	input, err := s.SnapshotEvidenceInput(ctx, snap, assets, opts)
	if m := pipelineMetrics(ctx); m != nil {
		m.SnapshotReadPages += input.Manifest.ReadPages
		m.SnapshotReadBytes += input.Manifest.RawBytes
		m.JSONDecodes += input.Manifest.JSONDecodeCount
		m.WireFrameDecodes += input.Manifest.WireFrameDecodeCount
		m.HTTPRequestParses += input.Manifest.HTTPRequestParseCount
		m.DNSMessageParses += input.Manifest.DNSMessageParseCount
	}
	if err == nil && input.Reason == "" && cacheable && persist {
		if saved, encodeErr := encodePreprocessed(input, key); encodeErr == nil {
			if saveErr := putRecord(ctx, s.Store, "evidence_preprocess", key, snap.EventID, saved); saveErr != nil {
				input.Manifest.addIssue(SnapshotInputIssue{Code: "preprocess_cache_write_failed", Stage: "persist", Retryable: true})
			}
		} else {
			input.Manifest.addIssue(SnapshotInputIssue{Code: "preprocess_cache_budget_or_encoding", Stage: "persist"})
		}
	}
	return input, err
}
