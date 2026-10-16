package service

import (
	"encoding/json"
	"testing"

	"vulnscan-backend/evidence"
)

func TestReportPromptPreservesFeatureAndSemanticBoundaries(t *testing.T) {
	for _, d := range evidence.Definitions() {
		f := evidence.Finding{FactID: d.ID, EvidenceContract: d.EvidenceContract, Status: evidence.Observed}
		entry := ReportEvidence{Kind: "fact", Finding: &f, FactID: d.ID, Name: d.Description}
		out := reportEvidencePromptEntry(entry)
		if out["feature_claim"] != d.FeatureClaim || out["cannot_prove"] != d.CannotProve {
			t.Fatalf("feature boundary omitted for %s", d.ID)
		}
	}
	for _, d := range evidence.SemanticDefinitions() {
		f := evidence.SemanticFinding{EvidenceContract: d.EvidenceContract, Slot: d.Key, StructureValidation: "passed", SemanticSupport: "support", BehaviorOutcome: "not_established"}
		out := reportEvidencePromptEntry(ReportEvidence{Kind: "semantic", Semantic: &f})
		if out["structure_validation"] != "passed" || out["behavior_outcome"] != "not_established" || out["cannot_prove"] != d.CannotProve {
			t.Fatalf("semantic boundary omitted for %s", d.Key)
		}
		if _, err := json.Marshal(out); err != nil {
			t.Fatal(err)
		}
	}
}
