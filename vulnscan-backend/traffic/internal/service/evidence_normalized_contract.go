package service

import "vulnscan-backend/evidence"

type NormalizedExecutionContract struct {
	SchemaVersion         string                   `json:"schema_version"`
	EventID               string                   `json:"event_id"`
	SnapshotIdentity      PhaseOneSnapshotSource   `json:"snapshot_identity"`
	InputDigest           string                   `json:"input_digest"`
	RuleVersions          map[string]string        `json:"rule_versions"`
	SemanticModelVersions []string                 `json:"semantic_model_versions"`
	SourceIndex           map[string]string        `json:"source_index"`
	SourceSets            map[string][]string      `json:"source_sets"`
	Coverage              []PreparedFamilyCoverage `json:"coverage"`
	Diagnostics           []SnapshotInputIssue     `json:"diagnostics"`
	LedgerPath            string                   `json:"ledger_path"`
}

func normalizedExecutionContract(snap EvidenceSnapshot, input SnapshotEvidenceInput, out PreparedEvidenceExecution) *NormalizedExecutionContract {
	c := &NormalizedExecutionContract{SchemaVersion: "normalized-evidence-execution-1.0", EventID: snap.EventID,
		SnapshotIdentity: phaseOneSnapshotSource(snap), InputDigest: out.Evaluation.InputDigest,
		RuleVersions:          map[string]string{"F": evidence.RuleVersion, "S": evidence.SemanticVersion, "C": evidence.PhaseOneVersion, "normalization": evidence.NormalizationVersion},
		SemanticModelVersions: []string{}, SourceIndex: map[string]string{}, SourceSets: map[string][]string{}, Coverage: preparedFamilyCoverage(capturePreparedInputs(input)), Diagnostics: input.Manifest.Issues,
		LedgerPath: "Evidence.normalized_evidence"}
	if input.Manifest.PhaseOne != nil {
		for _, source := range input.Manifest.PhaseOne.Sources {
			if source.EventID == snap.EventID && source.Version == snap.Version && source.Watermark == snap.Watermark && source.RevisionWatermark == snap.RevisionWatermark {
				c.SnapshotIdentity = source
				break
			}
		}
	}
	if len(c.Coverage) == 0 {
		c.Coverage = out.Evaluation.InputCoverage
	}
	if out.Semantics.Result != nil && out.Semantics.Result.Calls > 0 {
		c.SemanticModelVersions = append(c.SemanticModelVersions, out.Semantics.ModelVersion)
	}
	for _, item := range out.Evidence.Normalized.Items {
		key := digest(item.SourceIDs)
		c.SourceIndex[item.ID] = key
		if _, ok := c.SourceSets[key]; !ok {
			c.SourceSets[key] = item.SourceIDs
		}
	}
	return c
}
