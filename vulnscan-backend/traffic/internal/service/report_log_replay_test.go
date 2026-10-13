package service

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	// The user disabled the report evidence checker. Replay must preserve the
	// model result and allow publication without applying the historical rules.
	a, err := decodeReportAssessment(string(log.Assessment), bundle)
	if err != nil {
		t.Fatalf("removed checker still blocked real report: %v", err)
	}
	if a.Probability == nil || *a.Probability != 55 {
		t.Fatal("model probability changed")
	}

	entries := map[string]ReportEvidence{}
	for _, e := range bundle.Entries {
		entries[e.ID] = e
	}
	if err := validateReportNumbers("14条命中全部集中在2026-10-13 12:30五分钟桶内，平均间隔0.12秒", []string{"E003"}, entries); err != nil {
		t.Fatalf("real five-minute-bucket false positive: %v", err)
	}
}
