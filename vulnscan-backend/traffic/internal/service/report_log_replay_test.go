package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Optional replay uses local downloaded logs; real materials are never checked in.
func TestReportDownloadedAssessmentReplay(t *testing.T) {
	root := os.Getenv("REPORT_REPLAY_LOG_DIR")
	if root == "" {
		t.Skip("set REPORT_REPLAY_LOG_DIR to downloaded event log directory")
	}
	const run = "64cb6d52dab26aa93d9fff74d2d1f465"
	raw, err := os.ReadFile(filepath.Join(root, "2-证据与权重日志", run, "evidence-selection.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle ReportEvidenceBundle
	var selection struct {
		Entries []struct {
			Entry ReportEvidence `json:"entry"`
		} `json:"entries"`
		SelectedIDs []string `json:"selected_ids"`
	}
	if err = json.Unmarshal(raw, &selection); err != nil {
		t.Fatal(err)
	}
	for _, item := range selection.Entries {
		bundle.Entries = append(bundle.Entries, item.Entry)
	}
	bundle.SelectedIDs = selection.SelectedIDs
	bundle.PolicyVersion = reportEvidenceVersion
	raw, err = os.ReadFile(filepath.Join(root, "3-模型输入输出日志", run, "llm-assessment-02.json"))
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Assessment      json.RawMessage `json:"assessment"`
		ValidationError string          `json:"validation_error"`
	}
	if err = json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	if log.ValidationError != "report_count_requires_numeric_citation" {
		t.Fatal("unexpected source regression")
	}
	// The old validator stopped at 五分钟桶. After fixing that false positive,
	// this particular answer exposes a genuine unsupported claim: 17 days on
	// E006, which lists 16 active dates. Do not approve it by widening scope.
	_, err = decodeReportAssessment(string(log.Assessment), bundle)
	if err == nil || !strings.Contains(err.Error(), "report_fact_numbers_not_in_cited_scope: value=17 refs=E006") {
		t.Fatalf("real unsupported active-day claim was not retained: %v", err)
	}
	entries := map[string]ReportEvidence{}
	for _, e := range bundle.Entries {
		entries[e.ID] = e
	}
	if err := validateReportNumbers("14条命中全部集中在2026-10-13 12:30五分钟桶内，平均间隔0.12秒", []string{"E003"}, entries); err != nil {
		t.Fatalf("real five-minute-bucket false positive: %v", err)
	}
}
