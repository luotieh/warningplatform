package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Consume the frozen fixture without executing engines. Model prose below is
// only a validator unit fixture, never saved as a generated assessment report.
func TestOfflineReportUsesFrozenProjectionAndRejectsOverclaims(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "docs", "evidence-pipeline-v2", "mock-scenarios", "mock-01-c2-beacon")
	read := func(name string, dst any) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, dst); err != nil {
			t.Fatal(err)
		}
	}
	var b PreparedEvidenceBundle
	var f PreparedEvidenceExecution
	read("prepared-bundle.json", &b)
	read("normalized-result.json", &f)
	before, _ := json.Marshal(f)
	ctx, _ := json.Marshal(map[string]any{"event_id": b.Event.EventID, "synthetic": true})
	req, err := PrepareOfflineReport(b.Event, f, ctx)
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]json.RawMessage
	_ = json.Unmarshal(req.User, &input)
	if len(input["key_evidence"]) == 0 || !strings.Contains(req.System, "受控Stub") {
		t.Fatal("production projection or provenance lost")
	}
	a := validPipelineAssessment(f.Evidence)
	a.Gaps = []string{"合成数据；S为受控Stub；IOC为合成情报；未证明攻击成功；模型估计未校准"}
	a.Interpretations = nil
	raw, _ := json.Marshal(a)
	if _, err = ValidateOfflineReport(string(raw), b.Event, f, "test-only-not-real"); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ReportAssessment){
		"unknown_reference":       func(v *ReportAssessment) { v.Supporting[0].EvidenceIDs = []string{"F999"} },
		"invented_number":         func(v *ReportAssessment) { v.Supporting[0].Explanation = "观察999999999次通信" },
		"success_claim":           func(v *ReportAssessment) { v.Supporting[0].Explanation = "已感染" },
		"missing_stub_disclosure": func(v *ReportAssessment) { v.Gaps = []string{"合成IOC情报"} },
	} {
		t.Run(name, func(t *testing.T) {
			var copy ReportAssessment
			_ = json.Unmarshal(raw, &copy)
			change(&copy)
			bad, _ := json.Marshal(copy)
			if _, err := ValidateOfflineReport(string(bad), b.Event, f, "test-only-not-real"); err == nil {
				t.Fatal("invalid model report accepted")
			}
		})
	}
	changed := strings.TrimSuffix(string(raw), "}") + `,"evidence_risk":{"score":99}}`
	if _, err = ValidateOfflineReport(changed, b.Event, f, "test-only-not-real"); err == nil {
		t.Fatal("model score override accepted")
	}
	after, _ := json.Marshal(f)
	if string(before) != string(after) {
		t.Fatal("frozen output was mutated")
	}
	if _, err = PrepareOfflineReport(b.Event, f, json.RawMessage(`{"event_id":"another-event"}`)); err == nil {
		t.Fatal("cross-event context accepted")
	}
}
