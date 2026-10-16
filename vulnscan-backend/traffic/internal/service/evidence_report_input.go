package service

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// PrepareReportEvidence reads the snapshot once and shares its exact version
// with both the deterministic engine and the existing model projection.
// Reports schedule all 59F/23S; C remains restricted to the phase-one registry.
// Missing dependencies cannot become negative evidence.
func (s Services) PrepareReportEvidence(ctx context.Context, event domain.Event) (string, error) {
	prepared, err := s.prepareReportInput(ctx, event)
	return prepared.Context, err
}

type PreparedEvidenceExecution struct {
	Contract     *NormalizedExecutionContract `json:"contract,omitempty"`
	Context      string
	AssetSection string
	Evaluation   SnapshotFactEvaluation
	Semantics    ReportSemanticEvaluation
	Evidence     ReportEvidenceBundle
}

// Existing report callers and offline replay share the same result type.
type preparedReportInput = PreparedEvidenceExecution

func (s Services) prepareReportInput(ctx context.Context, event domain.Event) (preparedReportInput, error) {
	return s.prepareReportInputMode(ctx, event, true)
}

func (s Services) prepareReportInputMode(ctx context.Context, event domain.Event, persist bool) (preparedReportInput, error) {
	return (EvidencePipeline{Services: s}).executeEvent(ctx, event, EvidencePipelineOptions{Persist: persist})
}

func (s Services) executeEvidencePipeline(ctx context.Context, event domain.Event, persist bool) (preparedReportInput, error) {
	snapshotTiming := pipelineMeasure(ctx, "current_snapshot")
	snap, err := s.EvidenceSnapshot(ctx, event.EventID, 0)
	snapshotTiming()
	if err != nil {
		if err.Error() != "legacy_event" {
			return preparedReportInput{}, err
		}
		// Old events have no immutable membership watermark. Keep the existing
		// projection, but never label reconstructed samples as verified inputs.
		c := decodeEventContext(event.Context)
		occurrences, _ := c["occurrences"].([]any)
		c["statistics_quality"] = "unverified"
		c["evidence_note"] = "历史统计未核验；仅扫描已保存明细，不代表全量原始命中"
		c["input_manifest"] = map[string]any{"available_hits": len(occurrences), "declared_hits": c["occurrence_count"], "statistics_quality": "unverified"}
		c["algorithm_evidence"] = map[string]any{"status": "unavailable", "reason": "legacy_snapshot_unverified"}
		semantics := ReportSemanticEvaluation{Status: "unavailable", Reason: "legacy_snapshot_unverified", InputMode: evidence.SemanticRaw, AdapterVersion: semanticAdapterVersion}
		c["semantic_evidence"] = reportSemanticSummary(semantics)
		b, err := json.Marshal(c)
		manifest := SnapshotEvidenceManifest{AdapterVersion: reportSnapshotAdapterVersion, Coverage: "unverified", FactCoverage: snapshotUnavailableCoverage(evidence.SupportedFacts(), "legacy_snapshot_unverified")}
		manifest.addIssue(SnapshotInputIssue{Code: "legacy_snapshot_unverified", Stage: "load_snapshot"})
		evaluation := SnapshotFactEvaluation{Status: "unavailable", Reason: "legacy_snapshot_unverified", Manifest: manifest}
		return preparedReportInput{Context: string(b), AssetSection: assetMatchContext(event, s.Store.ListAssets()), Evaluation: evaluation, Semantics: semantics, Evidence: buildReportEvidence(event, EvidenceSnapshot{EventID: event.EventID, Context: c}, evaluation, semantics)}, err
	}
	source, err := s.collectPipelineInputs(ctx, event, snap)
	if err != nil {
		return preparedReportInput{}, err
	}
	return s.executePreparedPipeline(ctx, source, func() (SnapshotEvidenceInput, error) {
		return s.loadPipelinePrepared(ctx, source, persist)
	}, persist, true, persist)
}

type pipelinePreparedSource struct {
	Event    domain.Event
	Snapshot EvidenceSnapshot
	Assets   []domain.Asset
	Options  SnapshotEvidenceOptions
	History  ReportHistory
	Config   evidence.Config
}

func (s Services) collectPipelineInputs(ctx context.Context, event domain.Event, snap EvidenceSnapshot) (pipelinePreparedSource, error) {
	var err error
	// One registry read serves all hit/scope bindings in this evaluation. Cache
	// identity includes the registry, so enrollment or address changes invalidate it.
	assetCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	assets, assetErr := s.Store.ListAssetsContext(assetCtx)
	cancel()
	if ctx.Err() != nil {
		return pipelinePreparedSource{}, ctx.Err()
	}
	options := DefaultSnapshotEvidenceOptions()
	options.ReportMaterialMode = true
	options.DeferIndependentFacts = !s.LegacyReportEvidence
	if !s.LegacyReportEvidence {
		options.StreamFeatures = true
		options.MaxSnapshotBytes = contextPipelineLimits(ctx).SnapshotBytes
		options.MaxFeatureBytes = contextPipelineLimits(ctx).FeatureBytes
	}
	options.ReportSchedules = s.ReportSchedules
	if assetErr != nil {
		issue := snapshotIssueCause(SnapshotInputIssue{Code: "asset_registry_read_failed", Stage: "load_assets", Retryable: true}, assetErr)
		options.RegistryIssue = &issue
		assets = nil
	}
	options.Facts = evidence.SupportedFacts()
	options.CaptureSemantic = true
	options.Supplemental, options.SupplementalIssue, err = s.loadSnapshotSupplemental(ctx, snap)
	if err != nil {
		return pipelinePreparedSource{}, err
	}
	options.Sources, options.SourceIssue, err = s.loadEvidenceSources(ctx)
	if err != nil {
		return pipelinePreparedSource{}, err
	}
	config := evidence.DefaultConfig()
	config.Policies = map[evidence.FactID]map[string]float64{
		"F_BEACON_JITTER":            {"ljung_box_lags": 3, "median_relative_tolerance": 0.25},
		"F_PORT_SEQUENCE":            {"difference_entropy_threshold": 3},
		"F_SMALL_PACKET":             {"small_payload_bytes": 64},
		"F_RATE_RAMP":                {"window_seconds": 300},
		"F_FAILED_TO_ACTIVE":         {"min_failures": 2},
		"F_BRAND_IMPOSTOR":           {"max_edit_distance": 1},
		"F_MULTI_ASSET_IOC":          {"cluster_window_seconds": 3600},
		"F_MULTI_ASSET_DIST":         {"subnet_entropy_min": 1},
		"F_TIME_COORDINATION":        {"bucket_seconds": 60, "max_lag_bins": 5},
		"F_COORD_FANOUT":             {"handoff_seconds": 300},
		"F_INFECTION_CHAIN":          {"chain_window_seconds": 300},
		"F_COORD_PATTERN_RECURRENCE": {"bucket_seconds": 300},
		"F_HIST_SCHEDULE_MATCH":      {"kl_threshold": 0.5},
		"F_HIST_COORD_PARAM_MATCH":   {"parameter_relative_tolerance": 0.25},
	}
	historyTiming := pipelineMeasure(ctx, "history_metadata")
	history := s.loadReportHistoryMode(ctx, event, snap, assets, !s.LegacyReportEvidence)
	historyTiming()
	if m := pipelineMetrics(ctx); m != nil {
		m.HistoryMetadataPages += history.ReadPages
	}
	s.freezePipelineHistory(ctx, &history)
	if ctx.Err() != nil {
		return pipelinePreparedSource{}, ctx.Err()
	}
	options.PlatformHistory = &history
	return pipelinePreparedSource{Event: event, Snapshot: snap, Assets: assets, Options: options, History: history, Config: config}, nil
}

func (s Services) loadPipelinePrepared(ctx context.Context, source pipelinePreparedSource, persist bool) (SnapshotEvidenceInput, error) {
	snap, assets, options, history := source.Snapshot, source.Assets, source.Options, source.History
	input, err := s.pipelinePreprocessed(ctx, snap, assets, options, persist)
	if err != nil {
		return input, err
	}
	if !s.LegacyReportEvidence {
		if input.Manifest.PhaseOne != nil && !input.Manifest.PhaseOne.Expanded {
			membershipComplete := input.Manifest.Coverage == "complete" || (input.Manifest.StreamVersion != "" && input.Manifest.LoadedHits == input.Manifest.DeclaredHits && input.Manifest.UnresolvedHits == input.Manifest.PhaseOneExcludedHits)
			input.Manifest.PhaseOne.Complete = input.Manifest.PhaseOne.Complete && membershipComplete
			timeline, timelineErr := s.pipelineTimeline(ctx, snap, *input.Manifest.PhaseOne, history, assets, persist)
			if timelineErr != nil && ctx.Err() != nil {
				return input, ctx.Err()
			}
			if timelineErr != nil {
				timeline.Complete = false
				timeline.Diagnostics = append(timeline.Diagnostics, "timeline_read_failed")
			}
			input.Manifest.PhaseOne = &timeline
		}
		if input.Manifest.PhaseOne == nil {
			input.Manifest.PhaseOne = &PhaseOneMaterials{Expanded: true, Diagnostics: []string{"current_wire_materials_unavailable"}}
		}
		// Parse HTTP/DNS bodies and verify decode chains in L2. L3 only binds
		// computed F dependencies and plans slots from these prepared materials.
		materialInput := input
		materialInput.Manifest.PhaseOneFactsPrepared = true
		prepared := buildSnapshotSemanticRequest(snap, materialInput, &evidence.Result{}, evidence.SemanticRaw)
		input.PreparedSemantics = &prepared
	}
	return input, nil
}

// executePreparedPipeline is shared by formal reports and storage-free replay.
// load returns completed L2 inputs; no rule is allowed to fetch missing inputs.
func (s Services) executePreparedPipeline(ctx context.Context, source pipelinePreparedSource, load func() (SnapshotEvidenceInput, error), persist, readCache, executeModel bool) (preparedReportInput, error) {
	event, snap, assets, options, history, config := source.Event, source.Snapshot, source.Assets, source.Options, source.History, source.Config
	assetVersions := append([]domain.Asset(nil), assets...)
	sort.Slice(assetVersions, func(i, j int) bool { return assetVersions[i].ID < assetVersions[j].ID })
	key := digest([]any{PreparedEvidenceSchemaVersion, snap.EventID, snap.Version, snap.Watermark, snap.RevisionWatermark, evidence.RuleVersion, reportSnapshotAdapterVersion, config, options, assetVersions, options.Supplemental, options.SupplementalIssue, options.Sources, options.SourceIssue, options.RegistryIssue})
	var record store.AggregateRecord
	var exists bool
	var err error
	if readCache {
		record, exists, err = s.Store.AggregateRecord(ctx, "evidence_result", key)
	}
	cacheAvailable := readCache && err == nil
	if err != nil {
		exists = false
		log.Printf("[evidence] cache_read_failed event=%s snapshot=%d", snap.EventID, snap.Version)
	}
	var evaluation SnapshotFactEvaluation
	var sharedInput *SnapshotEvidenceInput
	loadPrepared := func() (SnapshotEvidenceInput, error) {
		if sharedInput != nil {
			return *sharedInput, nil
		}
		loaded, loadErr := load()
		if loadErr == nil {
			sharedInput = &loaded
		}
		return loaded, loadErr
	}
	resultPersisted := false
	if exists {
		if err := json.Unmarshal(record.Value, &evaluation); err != nil {
			exists = false
		}
		if evaluation.Manifest.SnapshotVersion != snap.Version || evaluation.Manifest.AdapterVersion != reportSnapshotAdapterVersion || (evaluation.Result != nil && evaluation.Result.RuleVersion != evidence.RuleVersion) || evaluation.Status == "evaluated" && evaluation.Result == nil || len(evaluation.Manifest.FactCoverage) < len(options.Facts) {
			exists = false
		}
		if exists {
			evaluation.CacheHit = true
			resultPersisted = true
		} else {
			log.Printf("[evidence] cache_invalid event=%s snapshot=%d", snap.EventID, snap.Version)
		}
	}
	if options.SupplementalIssue != nil && options.SupplementalIssue.Retryable {
		exists = false
	}
	if !persist || options.SourceIssue != nil && options.SourceIssue.Retryable || options.RegistryIssue != nil {
		exists = false
	}
	if !exists {
		resultPersisted = false
		loaded, loadErr := loadPrepared()
		sharedInput = &loaded
		factTiming := pipelineMeasure(ctx, "deterministic_facts")
		evaluation, err = evaluateSnapshotFactInput(ctx, snap, loaded, loadErr, options, config)
		wire := capturePreparedInputs(loaded)
		evaluation.InputCoverage = preparedFamilyCoverage(wire)
		evaluation.InputDigest = digest([]any{wire.Request, wire.HTTP, wire.PlatformHistory, config})
		factTiming()
		if err != nil {
			if ctx.Err() != nil {
				return preparedReportInput{}, ctx.Err()
			}
			// Evidence is an independent subsystem: fail closed for its claims,
			// preserve the original report data and persist a correlated failure.
			failureKey := snapshotKey(snap.EventID, snap.Version)
			failure := map[string]any{"event_id": snap.EventID, "snapshot_version": snap.Version, "at": time.Now().UTC(), "adapter_version": reportSnapshotAdapterVersion, "reason": evaluation.Reason, "manifest": evaluation.Manifest}
			if persist {
				if saveErr := putRecord(ctx, s.Store, "evidence_failure", failureKey, snap.EventID, failure); saveErr != nil {
					log.Printf("[evidence] failure_record_write_failed event=%s snapshot=%d", snap.EventID, snap.Version)
				}
			}
			log.Printf("[evidence] input_failed event=%s snapshot=%d reason=%s", snap.EventID, snap.Version, evaluation.Reason)
			cacheAvailable = false
		}
		if persist && cacheAvailable && (options.SupplementalIssue == nil || !options.SupplementalIssue.Retryable) && (options.SourceIssue == nil || !options.SourceIssue.Retryable) && options.RegistryIssue == nil {
			if err = putRecord(ctx, s.Store, "evidence_result", key, snap.EventID, evaluation); err != nil {
				evaluation.Manifest.addIssue(SnapshotInputIssue{Code: "result_cache_write_failed", Stage: "persist", Retryable: true})
				log.Printf("[evidence] result_cache_write_failed event=%s snapshot=%d", snap.EventID, snap.Version)
			} else {
				resultPersisted = true
			}
		}
	}
	if readCache && !cacheAvailable {
		evaluation.Manifest.addIssue(SnapshotInputIssue{Code: "result_not_cached", Stage: "persist", Retryable: true})
	}
	if evaluation.CacheHit {
		if m := pipelineMetrics(ctx); m != nil {
			m.CacheHits["facts"]++
		}
	}
	if ctx.Err() != nil {
		return preparedReportInput{}, ctx.Err()
	}
	if !s.LegacyReportEvidence {
		// Prepare independent F evidence before S planning. This does not call the
		// model or write caches; the expanded manifest is reused by the final C join.
		phaseTiming := pipelineMeasure(ctx, "independent_facts")
		preparedPhase := PhaseOneEvaluation{Materials: PhaseOneMaterials{Complete: false, Diagnostics: []string{"current_wire_materials_unavailable"}}}
		if evaluation.Manifest.PhaseOne != nil {
			preparedPhase.Materials = *evaluation.Manifest.PhaseOne
		}
		preparedFacts, phasePrepErr := computePhaseOneFacts(ctx, snap, preparedPhase.Materials, preparedPhase.Materials, history)
		preparedPhase.Facts = preparedFacts
		phaseTiming()
		if phasePrepErr != nil {
			return preparedReportInput{}, phasePrepErr
		}
		evaluation.Manifest.PhaseOne = &preparedPhase.Materials
		evaluation.Manifest.PhaseOneFactsPrepared = true
		if evaluation.Result != nil {
			additional, timeErr := pipelineIndependentTemporalFacts(ctx, snap, preparedPhase.Materials)
			if timeErr != nil {
				return preparedReportInput{}, timeErr
			}
			replacements := append(append([]evidence.Finding(nil), preparedPhase.Facts...), additional...)
			evaluation.Result.Findings = mergePipelineFacts(evaluation.Result.Findings, replacements)
			evaluation.Result.Executions = nil
			for _, f := range evaluation.Result.Findings {
				status := "executed"
				if f.Status == evidence.Missing {
					status = "skipped"
				}
				evaluation.Result.Executions = append(evaluation.Result.Executions, evidence.Execution{FactID: f.FactID, Scope: f.Scope, Status: status, ReasonCode: f.ReasonCode})
			}
			evaluation.Manifest.FactCoverage = snapshotFactCoverage(evidence.Request{Facts: options.Facts}, *evaluation.Result)
		}
		key = digest([]any{key, evidence.PhaseOneVersion, preparedPhase.Facts, preparedPhase.Materials})
		// Diagnostics and S planning must reference a persisted result containing
		// independent-contact F values, rather than the preliminary packet view.
		resultPersisted = false
		if persist {
			if cacheErr := putRecord(ctx, s.Store, "evidence_result", key, snap.EventID, evaluation); cacheErr == nil {
				resultPersisted = true
			} else {
				evaluation.Manifest.addIssue(SnapshotInputIssue{Code: "phase_one_fact_cache_write_failed", Stage: "persist", Retryable: true})
			}
		}
	}
	evaluation.Manifest.History = &ReportHistoryDiagnostics{Status: history.Status, Reason: history.Reason, Candidates: history.CandidateCount, Matched: len(history.Rows), Excluded: history.ExcludedCount, Truncated: history.Truncated}
	if history.Status == "unavailable" {
		issue := SnapshotInputIssue{Code: history.Reason, Stage: "load_history", Retryable: history.Reason == "history_query_failed"}
		if history.Issue != nil {
			issue = *history.Issue
		}
		evaluation.Manifest.addIssue(issue)
	}
	diagnostic := SnapshotEvidenceDiagnostics{EventID: snap.EventID, SnapshotVersion: snap.Version, At: time.Now().UTC(), Status: evaluation.Status, Reason: evaluation.Reason, ResultKey: key, ResultPersisted: resultPersisted, Manifest: evaluation.Manifest}
	if persist {
		if saveErr := putRecord(ctx, s.Store, "evidence_diagnostics", snapshotKey(snap.EventID, snap.Version), snap.EventID, diagnostic); saveErr != nil {
			evaluation.Manifest.addIssue(SnapshotInputIssue{Code: "diagnostics_write_failed", Stage: "persist", Retryable: true})
			log.Printf("[evidence] diagnostics_write_failed event=%s snapshot=%d", snap.EventID, snap.Version)
		}
	}
	manifest := make(map[string]any, len(snap.Manifest)+1)
	for k, v := range snap.Manifest {
		manifest[k] = v
	}
	manifest["algorithm_evidence"] = map[string]any{
		"evidence_result_key": key, "adapter_version": reportSnapshotAdapterVersion,
		"rule_version": evidence.RuleVersion, "registry_version": evaluation.Manifest.RegistryVersion,
		"status": evaluation.Status, "reason": evaluation.Reason,
		"read_pages": evaluation.Manifest.ReadPages, "revision_batches": evaluation.Manifest.RevisionBatches,
		"max_hits": options.MaxHits, "max_raw_bytes": options.MaxRawBytes,
		"issue_count": evaluation.Manifest.IssueCount, "omitted_issues": evaluation.Manifest.OmittedIssues, "supplemental_version": evaluation.Manifest.SupplementalVersion,
		"source_registry_version":   evaluation.Manifest.SourceRegistryVersion,
		"evidence_result_persisted": resultPersisted, "diagnostics_key": snapshotKey(snap.EventID, snap.Version),
	}
	snap.Manifest = manifest
	if audit := reportLogFrom(ctx); audit != nil {
		audit.meta["snapshot_version"] = snap.Version
		audit.write("fact-preparation.json", evaluation)
		audit.write("snapshot-materials.json", map[string]any{"snapshot": snap, "history": history, "material_cache_key": key})
	}
	semantics, semanticErr := s.prepareReportSemantics(ctx, snap, evaluation, key, sharedInput, persist, resultPersisted, loadPrepared, executeModel)
	if semantics.CacheHit {
		if m := pipelineMetrics(ctx); m != nil {
			m.CacheHits["semantic_result"]++
		}
	}
	if semanticErr != nil && ctx.Err() != nil {
		return preparedReportInput{}, ctx.Err()
	}
	manifest["semantic_evidence"] = map[string]any{"result_key": semantics.ResultKey, "adapter_version": semantics.AdapterVersion, "input_mode": semantics.InputMode, "status": semantics.Status, "result_persisted": semantics.ResultPersisted}
	projected, err := projectReportEvidence(snap, evaluation, semantics)
	if evaluation.InputDigest == "" {
		evaluation.InputDigest = key
	}
	if sharedInput != nil {
		wire := capturePreparedInputs(*sharedInput)
		// Storage lookup keys include collector options. The public algorithm
		// digest binds actual typed inputs and parameters, independent of how
		// they were fetched and whether a cache was used.
		evaluation.InputDigest = digest([]any{wire.Request, wire.HTTP, wire.PlatformHistory, config})
	}
	normalizeTiming := pipelineMeasure(ctx, "normalize_project")
	bundle := buildReportEvidence(event, snap, evaluation, semantics, history)
	normalizeTiming()
	var phaseOne *PhaseOneEvaluation
	if !s.LegacyReportEvidence {
		jointTiming := pipelineMeasure(ctx, "joint_c")
		executed, phaseErr := s.ExecutePhaseOne(ctx, snap, evaluation, semantics, history, assets, persist)
		jointTiming()
		if phaseErr != nil {
			return preparedReportInput{}, phaseErr
		}
		phaseOne = &executed
		if err == nil {
			projected, err = phaseOneContext(projected, executed)
		}
	}
	assetSection := normalizeReportAssetSection(assetMatchContext(event, assets))
	bundle.PhaseOne = phaseOne
	attachPipelineJointNormalization(&bundle)
	if !s.LegacyReportEvidence {
		e := boundedPipelineEssence(bundle)
		bundle.Essence = &e
	}
	out := preparedReportInput{Context: projected, AssetSection: assetSection, Evaluation: evaluation, Semantics: semantics, Evidence: bundle}
	contractTiming := pipelineMeasure(ctx, "normalized_contract_validate")
	if sharedInput != nil {
		out.Contract = normalizedExecutionContract(snap, *sharedInput, out)
	} else if !s.LegacyReportEvidence {
		out.Contract = normalizedExecutionContract(snap, SnapshotEvidenceInput{Manifest: evaluation.Manifest}, out)
	}
	if err == nil && !s.LegacyReportEvidence {
		err = validateNormalizedLedger(out)
	}
	contractTiming()
	return out, err
}

// Report-only wording: packet direction and an IOC label do not establish an
// attacking source or a compromised asset. Other callers retain their labels.
func normalizeReportAssetSection(s string) string {
	return strings.NewReplacer("受害侧", "观测资产", "威胁侧", "通联对端").Replace(s)
}

func projectReportEvidence(snap EvidenceSnapshot, facts SnapshotFactEvaluation, semantics ReportSemanticEvaluation) (string, error) {
	// The report uses its own normalized evidence and budget. Do not run the
	// shared dialogue projection, which discards records under a 6000-rune cap.
	context := map[string]any{"event_id": snap.EventID, "snapshot_version": snap.Version, "input_manifest": snap.Manifest, "algorithm_evidence": snapshotFactSummary(facts), "semantic_evidence": reportSemanticSummary(semantics)}
	for _, key := range []string{"ioc", "ioc_evidence"} {
		if value, ok := snap.Context[key]; ok {
			context[key] = value
		}
	}
	raw, err := json.Marshal(context)
	return string(raw), err
}

// Legacy projection retained for callers explicitly using its old envelope.
func projectLegacyReportEvidence(snap EvidenceSnapshot, facts SnapshotFactEvaluation, semantics ReportSemanticEvaluation) (string, error) {
	factSummary, semanticSummary := snapshotFactSummary(facts), reportSemanticSummary(semantics)
	// Whole entries compete under the existing shared 6000-character envelope;
	// retain explicit omission totals and status instead of slicing JSON/text.
	for {
		projected, err := evidenceContextFromSnapshot(snap, map[string]any{"algorithm_evidence": factSummary, "semantic_evidence": semanticSummary})
		if err == nil {
			return projected, nil
		}
		// Keep at least one validated interpretation alongside the highest
		// priority fact before spending the shared budget on missing fact rows.
		if entries, ok := factSummary["findings"].([]map[string]any); ok && len(entries) > 1 {
			factSummary["findings"] = entries[:len(entries)-1]
			factSummary["omitted_findings"] = factSummary["total_findings"].(int) - len(entries) + 1
			continue
		}
		if entries, ok := semanticSummary["findings"].([]map[string]any); ok && len(entries) > 0 {
			semanticSummary["findings"] = entries[:len(entries)-1]
			semanticSummary["omitted_findings"] = semanticSummary["total_findings"].(int) - len(entries) + 1
			continue
		}
		if entries, ok := factSummary["findings"].([]map[string]any); ok && len(entries) > 0 {
			factSummary["findings"] = entries[:len(entries)-1]
			factSummary["omitted_findings"] = factSummary["total_findings"].(int) - len(entries) + 1
			continue
		}
		return "", err
	}
}

// Complete results remain in evidence_result; this projection is bounded and
// excludes internal hashes/IDs and per-hit source lists from the report prompt.
func snapshotFactSummary(evaluation SnapshotFactEvaluation) map[string]any {
	summary := map[string]any{
		"status": evaluation.Status, "reason": evaluation.Reason,
		"rule_version": evidence.RuleVersion, "adapter_version": reportSnapshotAdapterVersion,
		"snapshot_version": evaluation.Manifest.SnapshotVersion, "cache_hit": evaluation.CacheHit,
		"declared_hits": evaluation.Manifest.DeclaredHits, "loaded_hits": evaluation.Manifest.LoadedHits,
		"bound_hits": evaluation.Manifest.BoundHits, "unresolved_hits": evaluation.Manifest.UnresolvedHits,
		"coverage":               evaluation.Manifest.Coverage,
		"input_issue_count":      evaluation.Manifest.IssueCount,
		"missing_input_families": evaluation.Manifest.MissingInputs,
		"note":                   "由确定性程序对本版本已保存命中计算；不代表全部网络通信。missing表示证据不足，不能改写成行为不存在；周期性不能确认C2或设备失陷。",
	}
	if evaluation.Result == nil {
		return summary
	}
	findings := append([]evidence.Finding(nil), evaluation.Result.Findings...)
	priority := func(s evidence.Status) int {
		if s == evidence.Observed {
			return 0
		}
		if s == evidence.Missing {
			return 1
		}
		return 2
	}
	sort.SliceStable(findings, func(i, j int) bool { return priority(findings[i].Status) < priority(findings[j].Status) })
	const maxFindings = 8
	entries := make([]map[string]any, 0, min(len(findings), maxFindings))
	for i, f := range findings {
		if i == maxFindings {
			break
		}
		entries = append(entries, map[string]any{"fact_id": f.FactID, "scope": f.Scope, "window": f.Window, "status": f.Status, "eligibility": f.Eligibility, "quality": f.Quality, "measurements": f.Measurements, "parameters": f.Parameters, "reason_code": f.ReasonCode, "limitations": f.Limitations})
	}
	summary["findings"] = entries
	summary["total_findings"] = len(findings)
	summary["omitted_findings"] = len(findings) - len(entries)
	// Reserve most of the existing 6000-character projection for statistics,
	// IOC background and representative payloads. Omit whole findings only.
	for len(entries) > 0 {
		b, _ := json.Marshal(summary)
		if utf8.RuneCount(b) <= 2400 {
			break
		}
		entries = entries[:len(entries)-1]
		summary["findings"] = entries
		summary["omitted_findings"] = len(findings) - len(entries)
	}
	return summary
}
