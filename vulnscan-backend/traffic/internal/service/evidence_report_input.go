package service

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"time"
	"unicode/utf8"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

// PrepareReportEvidence reads the snapshot once and shares its exact version
// with both the deterministic engine and the existing model projection.
// Reports check all registered facts against shared inputs; missing dependencies
// remain explicit and cannot become negative evidence.
func (s Services) PrepareReportEvidence(ctx context.Context, event domain.Event) (string, error) {
	prepared, err := s.prepareReportInput(ctx, event)
	return prepared.Context, err
}

type preparedReportInput struct {
	Context      string
	AssetSection string
	Evaluation   SnapshotFactEvaluation
}

func (s Services) prepareReportInput(ctx context.Context, event domain.Event) (preparedReportInput, error) {
	return s.prepareReportInputMode(ctx, event, true)
}

func (s Services) prepareReportInputMode(ctx context.Context, event domain.Event, persist bool) (preparedReportInput, error) {
	snap, err := s.EvidenceSnapshot(ctx, event.EventID, 0)
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
		b, err := json.Marshal(c)
		manifest := SnapshotEvidenceManifest{AdapterVersion: snapshotAdapterVersion, Coverage: "unverified", FactCoverage: snapshotUnavailableCoverage(evidence.SupportedFacts(), "legacy_snapshot_unverified")}
		manifest.addIssue(SnapshotInputIssue{Code: "legacy_snapshot_unverified", Stage: "load_snapshot"})
		return preparedReportInput{Context: string(b), AssetSection: assetMatchContext(event, s.Store.ListAssets()), Evaluation: SnapshotFactEvaluation{Status: "unavailable", Reason: "legacy_snapshot_unverified", Manifest: manifest}}, err
	}
	// One registry read serves all hit/scope bindings in this evaluation. Cache
	// identity includes the registry, so enrollment or address changes invalidate it.
	assetCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	assets, assetErr := s.Store.ListAssetsContext(assetCtx)
	cancel()
	if ctx.Err() != nil {
		return preparedReportInput{}, ctx.Err()
	}
	options := DefaultSnapshotEvidenceOptions()
	if assetErr != nil {
		issue := snapshotIssueCause(SnapshotInputIssue{Code: "asset_registry_read_failed", Stage: "load_assets", Retryable: true}, assetErr)
		options.RegistryIssue = &issue
		assets = nil
	}
	options.Facts = evidence.SupportedFacts()
	options.Supplemental, options.SupplementalIssue, err = s.loadSnapshotSupplemental(ctx, snap)
	if err != nil {
		return preparedReportInput{}, err
	}
	options.Sources, options.SourceIssue, err = s.loadEvidenceSources(ctx)
	if err != nil {
		return preparedReportInput{}, err
	}
	config := evidence.DefaultConfig()
	assetVersions := append([]domain.Asset(nil), assets...)
	sort.Slice(assetVersions, func(i, j int) bool { return assetVersions[i].ID < assetVersions[j].ID })
	key := digest([]any{snap.EventID, snap.Version, snap.Watermark, snap.RevisionWatermark, evidence.RuleVersion, snapshotAdapterVersion, config, options, assetVersions, options.Supplemental, options.SupplementalIssue, options.Sources, options.SourceIssue, options.RegistryIssue})
	record, exists, err := s.Store.AggregateRecord(ctx, "evidence_result", key)
	cacheAvailable := err == nil
	if err != nil {
		exists = false
		log.Printf("[evidence] cache_read_failed event=%s snapshot=%d", snap.EventID, snap.Version)
	}
	var evaluation SnapshotFactEvaluation
	resultPersisted := false
	if exists {
		if err := json.Unmarshal(record.Value, &evaluation); err != nil {
			exists = false
		}
		if evaluation.Manifest.SnapshotVersion != snap.Version || evaluation.Manifest.AdapterVersion != snapshotAdapterVersion || (evaluation.Result != nil && evaluation.Result.RuleVersion != evidence.RuleVersion) || evaluation.Status == "evaluated" && evaluation.Result == nil || len(evaluation.Manifest.FactCoverage) < len(evidence.SupportedFacts()) {
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
		evaluation, err = s.EvaluateSnapshotFacts(ctx, snap, assets, options, config)
		if err != nil {
			if ctx.Err() != nil {
				return preparedReportInput{}, ctx.Err()
			}
			// Evidence is an independent subsystem: fail closed for its claims,
			// preserve the original report data and persist a correlated failure.
			failureKey := snapshotKey(snap.EventID, snap.Version)
			failure := map[string]any{"event_id": snap.EventID, "snapshot_version": snap.Version, "at": time.Now().UTC(), "adapter_version": snapshotAdapterVersion, "reason": evaluation.Reason, "manifest": evaluation.Manifest}
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
	if !cacheAvailable {
		evaluation.Manifest.addIssue(SnapshotInputIssue{Code: "result_not_cached", Stage: "persist", Retryable: true})
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
		"evidence_result_key": key, "adapter_version": snapshotAdapterVersion,
		"rule_version": evidence.RuleVersion, "registry_version": evaluation.Manifest.RegistryVersion,
		"status": evaluation.Status, "reason": evaluation.Reason,
		"read_pages": evaluation.Manifest.ReadPages, "revision_batches": evaluation.Manifest.RevisionBatches,
		"max_hits": options.MaxHits, "max_raw_bytes": options.MaxRawBytes,
		"issue_count": evaluation.Manifest.IssueCount, "omitted_issues": evaluation.Manifest.OmittedIssues, "supplemental_version": evaluation.Manifest.SupplementalVersion,
		"source_registry_version":   evaluation.Manifest.SourceRegistryVersion,
		"evidence_result_persisted": resultPersisted, "diagnostics_key": snapshotKey(snap.EventID, snap.Version),
	}
	snap.Manifest = manifest
	projected, err := evidenceContextFromSnapshot(snap, map[string]any{"algorithm_evidence": snapshotFactSummary(evaluation)})
	return preparedReportInput{Context: projected, AssetSection: assetMatchContext(event, assets), Evaluation: evaluation}, err
}

// Complete results remain in evidence_result; this projection is bounded and
// excludes internal hashes/IDs and per-hit source lists from the report prompt.
func snapshotFactSummary(evaluation SnapshotFactEvaluation) map[string]any {
	summary := map[string]any{
		"status": evaluation.Status, "reason": evaluation.Reason,
		"rule_version": evidence.RuleVersion, "adapter_version": snapshotAdapterVersion,
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
