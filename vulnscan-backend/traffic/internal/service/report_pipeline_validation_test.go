package service

import (
	"strings"
	"testing"
)

func TestPipelineProbabilityReasonIncludesReferencedBackground(t *testing.T) {
	b := ReportEvidenceBundle{
		Entries: []ReportEvidence{
			{ID: "F002", Kind: "fact", Status: "observed", Result: "历史97条命中"},
			{ID: "O003", Kind: "observation", Result: "远程端口443"},
			{ID: "O004", Kind: "observation", Result: "远程端口8443"},
		},
		Essence: &ReportEssenceBundle{Items: []ReportEssence{{ID: "F002"}, {ID: "O003"}, {ID: "O004"}}},
	}
	a := ReportAssessment{Target: "malicious_activity", ThreatType: "suspicious_contact", Verdict: "suspicious", Stage: "contact",
		ProbabilityReason: "历史97条命中，远程端口443",
		Supporting:        []ReportReason{{EvidenceIDs: []string{"F002"}, Explanation: "历史97条命中"}},
		Alternatives:      []ReportReason{{EvidenceIDs: []string{"O003"}, Explanation: "远程端口443"}},
	}
	if err := validatePipelineAssessment(a, b); err != nil {
		t.Fatal(err)
	}
	t.Run("background alone", func(t *testing.T) {
		copy := a
		copy.Supporting = nil
		if err := validatePipelineAssessment(copy, b); err == nil || err.Error() != "report_probability_without_evidence" {
			t.Fatalf("unexpected: %v", err)
		}
	})
	t.Run("unreferenced number", func(t *testing.T) {
		copy := a
		copy.ProbabilityReason = "远程端口8443"
		if err := validatePipelineAssessment(copy, b); err == nil || !strings.Contains(err.Error(), "report_fact_numbers_not_in_cited_scope") {
			t.Fatalf("unexpected: %v", err)
		}
	})
	t.Run("detail reference", func(t *testing.T) {
		copy := a
		copy.Alternatives = []ReportReason{{EvidenceIDs: []string{"D012"}, Explanation: "远程端口443"}}
		if err := validatePipelineAssessment(copy, b); err == nil || err.Error() != "report_unknown_or_duplicate_reference" {
			t.Fatalf("unexpected: %v", err)
		}
	})
}

func TestReportPromptDefinesNumericAndReferenceSources(t *testing.T) {
	for _, term := range []string{"scope.endpoint_id", "window", "D编号只是关联明细，不能作为正式证据引用", "不能仅引用零载荷占比"} {
		if !strings.Contains(evidenceReportSystemPrompt, term) {
			t.Errorf("missing: %s", term)
		}
	}
	if strings.Contains(evidenceReportSystemPrompt, "所有具体数值和地址仅在引用证据的result或measurements中取用") {
		t.Fatal("conflicting source rule")
	}
}
