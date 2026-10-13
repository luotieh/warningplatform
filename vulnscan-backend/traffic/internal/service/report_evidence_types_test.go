package service

import (
	"strings"
	"testing"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

func TestReportEvidenceUsesTypedReferencesAndRegistryNames(t *testing.T) {
	_, _, bundle := reportTestBundle(t)
	names := map[evidence.FactID]string{}
	for _, definition := range evidence.Definitions() {
		names[definition.ID] = definition.Description
	}
	for _, entry := range bundle.Entries {
		prefix := map[string]string{"fact": "F", "semantic": "S", "intelligence": "I"}[entry.Kind]
		if prefix == "" || !strings.HasPrefix(entry.ID, prefix) {
			t.Fatalf("invalid report evidence: %+v", entry)
		}
		if entry.Kind == "fact" && entry.Name != names[entry.FactID] {
			t.Fatalf("renamed fact: %+v", entry)
		}
		if entry.Semantic != nil && entry.Name != reportSemanticName(entry.Semantic.Slot) {
			t.Fatal("renamed semantic slot")
		}
	}
	doc := ReportDocument{LayoutVersion: reportFivePartLayout, Evidence: bundle, Assessment: validReportAssessment(bundle)}
	text := renderReportMarkdown(doc)
	for _, id := range bundle.SelectedIDs {
		for _, entry := range bundle.Entries {
			if entry.ID == id && !strings.Contains(text, id+"【"+entry.Name+"】") {
				t.Fatalf("missing title: %s", id)
			}
		}
	}
	snap := EvidenceSnapshot{Version: 1, Count: 1, Context: map[string]any{"ioc": map[string]any{"ioc_value": "example.org"}}, Evidence: []map[string]any{{"payload_hex": "0102", "protocol": "UDP"}}}
	intel := buildReportEvidence(domain.Event{}, snap, SnapshotFactEvaluation{}, ReportSemanticEvaluation{})
	if len(intel.Entries) != 1 || intel.Entries[0].Kind != "intelligence" || intel.Entries[0].ID != "I001" {
		t.Fatalf("raw observation entered key evidence: %+v", intel.Entries)
	}
}
