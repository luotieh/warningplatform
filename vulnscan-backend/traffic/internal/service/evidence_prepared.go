package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
)

const PreparedEvidenceSchemaVersion = "prepared-evidence-bundle-1.1"

// PreparedEvidenceBundle is the complete L2/L3 boundary. It contains inputs,
// not accepted verdicts. Importing one does not authenticate its producer;
// wire verification belongs to the preprocessor that produces it.
// Missing families stay missing; execution never retrieves additional data.
type PreparedEvidenceBundle struct {
	SchemaVersion     string                   `json:"schema_version"`
	PreprocessVersion string                   `json:"preprocess_version"`
	InputDigest       string                   `json:"input_digest"`
	Event             domain.Event             `json:"event"`
	Snapshot          EvidenceSnapshot         `json:"snapshot"`
	Assets            []domain.Asset           `json:"assets"`
	Inputs            EvidencePreparedInputs   `json:"inputs"`
	History           ReportHistory            `json:"history"`
	HistoryIssue      *SnapshotInputIssue      `json:"history_issue,omitempty"`
	FactConfig        evidence.Config          `json:"fact_config"`
	SemanticOptions   ReportSemanticOptions    `json:"semantic_options"`
	JointConfig       evidence.PhaseOneConfig  `json:"joint_config"`
	Coverage          []PreparedFamilyCoverage `json:"coverage"`
}

// Seal binds the serializable input and execution configuration. This is a
// corruption/reproducibility check, not a signature or IOC reputation check.
func (b *PreparedEvidenceBundle) Seal() {
	b.InputDigest = ""
	b.InputDigest = digest(*b)
}

func (b PreparedEvidenceBundle) Validate() error {
	if b.SchemaVersion != PreparedEvidenceSchemaVersion || b.PreprocessVersion != evidencePreprocessVersion {
		return fmt.Errorf("prepared_schema_version_mismatch")
	}
	expected := b.InputDigest
	b.InputDigest = ""
	if expected == "" || expected != digest(b) {
		return fmt.Errorf("prepared_input_digest_mismatch")
	}
	s, m, r := b.Snapshot, b.Inputs.Manifest, b.Inputs.Request
	if s.EventID == "" || b.Event.EventID != s.EventID || r.EventID != s.EventID || s.Version <= 0 || r.SnapshotVersion != s.Version || m.SnapshotVersion != s.Version || m.Watermark != s.Watermark || m.RevisionWatermark != s.RevisionWatermark || m.AdapterVersion != reportSnapshotAdapterVersion {
		return fmt.Errorf("prepared_snapshot_binding_mismatch")
	}
	if m.PhaseOne == nil || !m.PhaseOne.Expanded || m.PhaseOneFactsPrepared {
		return fmt.Errorf("prepared_independent_inputs_not_ready_or_contain_verdicts")
	}
	if b.Inputs.SemanticMaterials == nil || b.Inputs.SemanticMaterials.EventID != s.EventID || b.Inputs.SemanticMaterials.SnapshotVersion != s.Version {
		return fmt.Errorf("prepared_semantic_materials_not_ready")
	}
	for _, subject := range b.Inputs.SemanticMaterials.Subjects {
		if len(subject.Facts) != 0 {
			return fmt.Errorf("prepared_semantic_inputs_contain_verdicts")
		}
	}
	if len(r.Facts) != len(evidence.SupportedFacts()) {
		return fmt.Errorf("prepared_fact_catalog_mismatch")
	}
	seen := map[evidence.FactID]bool{}
	for _, id := range r.Facts {
		seen[id] = true
	}
	for _, id := range evidence.SupportedFacts() {
		if !seen[id] {
			return fmt.Errorf("prepared_fact_catalog_mismatch")
		}
	}
	sources := map[string]PhaseOneSnapshotSource{}
	for _, source := range m.PhaseOne.Sources {
		key := snapshotKey(source.EventID, source.Version)
		if source.EventID == s.EventID && (source.Version != s.Version || source.Watermark != s.Watermark || source.RevisionWatermark != s.RevisionWatermark) {
			return fmt.Errorf("prepared_current_source_mismatch")
		}
		if prev, ok := sources[key]; ok && prev != source {
			return fmt.Errorf("prepared_source_version_conflict")
		}
		sources[key] = source
	}
	for _, c := range append(append([]PhaseOneContact(nil), m.PhaseOne.CurrentContacts...), m.PhaseOne.Contacts...) {
		source, ok := sources[snapshotKey(c.Snapshot.EventID, c.Snapshot.Version)]
		if !ok || c.Snapshot.Watermark != source.Watermark || c.Snapshot.RevisionWatermark != source.RevisionWatermark || c.HitID == "" || c.Time.IsZero() || c.Scope.AssetID == "" || c.Scope.DeviceID == "" || c.Scope.EndpointID == "" {
			return fmt.Errorf("prepared_contact_source_mismatch")
		}
	}
	if err := b.validateContractRelations(); err != nil {
		return err
	}
	return b.JointConfig.Validate()
}

func EncodePreparedEvidence(w io.Writer, b PreparedEvidenceBundle) error {
	if err := b.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if len(raw) > preprocessDecodedBytes {
		return fmt.Errorf("prepared_bundle_budget_exceeded")
	}
	n, err := w.Write(raw)
	if err == nil && n != len(raw) {
		return io.ErrShortWrite
	}
	return err
}

func DecodePreparedEvidence(r io.Reader) (PreparedEvidenceBundle, error) {
	var b PreparedEvidenceBundle
	raw, err := io.ReadAll(io.LimitReader(r, preprocessDecodedBytes+1))
	if err != nil {
		return b, err
	}
	if len(raw) > preprocessDecodedBytes {
		return b, fmt.Errorf("prepared_bundle_budget_exceeded")
	}
	if err = validatePreparedWire(raw); err != nil {
		return b, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&b); err != nil {
		return b, err
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return b, fmt.Errorf("prepared_trailing_json")
	}
	return b, b.Validate()
}

// PrepareEvidenceBundle uses the same collector and preprocessor as formal
// reports. It never invokes a model or writes records. All history fetching and
// independent-contact construction finish before this function returns.
func (p EvidencePipeline) PrepareEvidenceBundle(ctx context.Context, eventID string) (PreparedEvidenceBundle, error) {
	var b PreparedEvidenceBundle
	s := p.Services
	if s.LegacyReportEvidence {
		return b, fmt.Errorf("prepared_bundle_requires_v2_profile")
	}
	ctx = context.WithValue(ctx, pipelineLimitsKey{}, s.pipelineLimits())
	ctx, cancel := context.WithTimeout(ctx, s.pipelineLimits().TotalTimeout)
	defer cancel()
	event, ok := s.Store.GetEvent(eventID)
	if !ok {
		return b, fmt.Errorf("event_not_found")
	}
	snap, err := s.EvidenceSnapshot(ctx, eventID, 0)
	if err != nil {
		return b, err
	}
	source, err := s.collectPipelineInputs(ctx, event, snap)
	if err != nil {
		return b, err
	}
	input, err := s.loadPipelinePrepared(ctx, source, false)
	if err != nil {
		return b, err
	}
	cfg := source.Config
	if x := source.Options.Supplemental; x != nil && validateSnapshotSupplemental(snap, *x) == nil && x.Policies != nil {
		cfg.Policies = x.Policies
	}
	joint, err := s.phaseOneConfig()
	if err != nil {
		return b, err
	}
	sem := DefaultReportSemanticOptions()
	if s.ReportSemantics != nil {
		sem = *s.ReportSemantics
	}
	if sem.ModelVersion == "" && s.LLM != nil {
		sem.ModelVersion = s.LLM.Model
	}
	b = PreparedEvidenceBundle{SchemaVersion: PreparedEvidenceSchemaVersion, PreprocessVersion: evidencePreprocessVersion, Event: event, Snapshot: snap, Assets: source.Assets, Inputs: capturePreparedInputs(input), History: source.History, HistoryIssue: source.History.Issue, FactConfig: cfg, SemanticOptions: sem, JointConfig: joint}
	b.Coverage = preparedFamilyCoverage(b.Inputs)
	b.Seal()
	return b, b.Validate()
}

// A model is explicit and injected; nil produces a plan with skipped model
// execution. No Store, database, report generator or ambient model is used.
type PreparedExecutionOptions struct {
	// Empty retains the v1 injected-model behavior. Disabled never invokes a model.
	SemanticMode PreparedSemanticMode
	// Prepared execution has no storage. Persistence belongs to EvidencePipeline.
	Persist       bool
	SemanticModel evidence.SemanticModel
	CountTokens   func(system, user string) (int, error)
}

func ExecutePreparedEvidence(ctx context.Context, b PreparedEvidenceBundle, opts PreparedExecutionOptions) (PreparedEvidenceExecution, error) {
	if opts.Persist {
		return PreparedEvidenceExecution{}, fmt.Errorf("prepared_persistence_requires_formal_pipeline")
	}
	switch opts.SemanticMode {
	case "", PreparedSemanticDisabled, PreparedSemanticStub, PreparedSemanticLive:
	default:
		return PreparedEvidenceExecution{}, fmt.Errorf("prepared_invalid_semantic_mode")
	}
	if opts.SemanticMode == PreparedSemanticDisabled {
		opts.SemanticModel = nil
	}
	if (opts.SemanticMode == PreparedSemanticStub || opts.SemanticMode == PreparedSemanticLive) && opts.SemanticModel == nil {
		return PreparedEvidenceExecution{}, fmt.Errorf("prepared_semantic_model_required")
	}
	if err := b.Validate(); err != nil {
		return PreparedEvidenceExecution{}, err
	}
	// Clone through the public wire format: neither engines nor report builders
	// may mutate caller inputs or change later executions of this bundle.
	raw, err := json.Marshal(b)
	if err != nil {
		return PreparedEvidenceExecution{}, err
	}
	b, err = DecodePreparedEvidence(bytes.NewReader(raw))
	if err != nil {
		return PreparedEvidenceExecution{}, err
	}
	b.SemanticOptions.Config.CountTokens = opts.CountTokens
	s := Services{PhaseOnePolicy: &b.JointConfig, ReportOptions: &config.ReportOptions{}, ReportSemantics: &b.SemanticOptions, SemanticModel: opts.SemanticModel}
	limits := s.pipelineLimits()
	ctx = context.WithValue(ctx, pipelineLimitsKey{}, limits)
	ctx, cancel := context.WithTimeout(ctx, limits.TotalTimeout)
	defer cancel()
	metrics := EvidencePipelineMetrics{StageMS: map[string]int64{}, CacheHits: map[string]int{}}
	ctx = context.WithValue(ctx, pipelineMetricsKey{}, &metrics)
	input := restorePreparedInputs(b.Inputs)
	history := b.History
	history.Issue = b.HistoryIssue
	options := DefaultSnapshotEvidenceOptions()
	options.Facts, options.DeferIndependentFacts = evidence.SupportedFacts(), true
	options.ReportMaterialMode, options.CaptureSemantic = true, true
	options.PlatformHistory = &history
	source := pipelinePreparedSource{Event: b.Event, Snapshot: b.Snapshot, Assets: b.Assets, Options: options, History: history, Config: b.FactConfig}
	start := time.Now()
	out, err := s.executePreparedPipeline(ctx, source, func() (SnapshotEvidenceInput, error) { return input, nil }, false, false, opts.SemanticModel != nil)
	if err != nil {
		return out, err
	}
	audit := pipelineAudit(b.Event.EventID, out.Evaluation, out.Semantics)
	audit.Metrics, audit.ElapsedMS = metrics, time.Since(start).Milliseconds()
	if out.Semantics.Result != nil {
		audit.Metrics.SemanticModelCalls = out.Semantics.Result.Calls
	}
	audit.Key = digest([]any{EvidencePipelineVersion, b.InputDigest, out.Evidence.Normalized, out.Evidence.PhaseOne.Result})
	out.Evidence.Pipeline = &audit
	if err := ValidatePreparedExecution(b, out); err != nil {
		return out, err
	}
	return out, nil
}

type PreparedSemanticMode string

const (
	PreparedSemanticDisabled PreparedSemanticMode = "disabled"
	PreparedSemanticStub     PreparedSemanticMode = "stub"
	PreparedSemanticLive     PreparedSemanticMode = "live"
)
