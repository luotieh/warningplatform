package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"unicode/utf8"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

// PrepareReportEvidence reads the snapshot once and shares its exact version
// with both the deterministic engine and the existing model projection.
// This first integration runs only the two explicit inexpensive defaults.
func (s Services) PrepareReportEvidence(ctx context.Context, event domain.Event) (string, error) {
	prepared, err := s.prepareReportInput(ctx, event)
	return prepared.Context, err
}

type preparedReportInput struct {
	Context      string
	AssetSection string
}

func (s Services) prepareReportInput(ctx context.Context, event domain.Event) (preparedReportInput, error) {
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
		return preparedReportInput{Context: string(b), AssetSection: assetMatchContext(event, s.Store.ListAssets())}, err
	}
	// One registry read serves all hit/scope bindings in this evaluation. Cache
	// identity includes the registry, so enrollment or address changes invalidate it.
	assets := s.Store.ListAssets()
	options := DefaultSnapshotEvidenceOptions()
	config := evidence.DefaultConfig()
	assetVersions := append([]domain.Asset(nil), assets...)
	sort.Slice(assetVersions, func(i, j int) bool { return assetVersions[i].ID < assetVersions[j].ID })
	key := digest([]any{snap.EventID, snap.Version, snap.Watermark, snap.RevisionWatermark, evidence.RuleVersion, snapshotAdapterVersion, config, options, assetVersions})
	record, exists, err := s.Store.AggregateRecord(ctx, "evidence_result", key)
	if err != nil {
		return preparedReportInput{}, err
	}
	var evaluation SnapshotFactEvaluation
	if exists {
		if err := json.Unmarshal(record.Value, &evaluation); err != nil {
			return preparedReportInput{}, err
		}
		if evaluation.Manifest.SnapshotVersion != snap.Version || evaluation.Manifest.AdapterVersion != snapshotAdapterVersion || (evaluation.Result != nil && evaluation.Result.RuleVersion != evidence.RuleVersion) {
			return preparedReportInput{}, errors.New("cached evidence version mismatch")
		}
		evaluation.CacheHit = true
	} else {
		evaluation, err = s.EvaluateSnapshotFacts(ctx, snap, assets, options, config)
		if err != nil {
			return preparedReportInput{}, err
		}
		if err = putRecord(ctx, s.Store, "evidence_result", key, snap.EventID, evaluation); err != nil {
			return preparedReportInput{}, err
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
	}
	snap.Manifest = manifest
	projected, err := evidenceContextFromSnapshot(snap, map[string]any{"algorithm_evidence": snapshotFactSummary(evaluation)})
	return preparedReportInput{Context: projected, AssetSection: assetMatchContext(event, assets)}, err
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
		"coverage": evaluation.Manifest.Coverage,
		"note":     "由确定性程序对本版本已保存命中计算；不代表全部网络通信。missing表示证据不足，不能改写成行为不存在；周期性不能确认C2或设备失陷。",
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
