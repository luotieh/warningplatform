package monitoragent

import (
	"encoding/json"
	"testing"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/analyzer"
)

func TestBuildTamperResultJSONFirstRun(t *testing.T) {
	snap := PageSnapshot{
		URL:         "http://127.0.0.1:10000/11.txt",
		StatusCode:  200,
		Title:       "test",
		ContentHash: "abc123",
		VisibleText: "hello",
	}
	rawSnap, _ := json.Marshal(snap)
	out := &analyzer.Output{
		BaselineUpdate: &model.MonitorBaselineUpdate{
			Action:            "init",
			ContentHash:       "abc123",
			Title:             "test",
			StatusCode:        200,
			VisibleTextLength: 5,
		},
	}
	resultJSON := BuildTamperResultJSON(string(rawSnap), out, snap.URL)
	var m map[string]any
	if err := json.Unmarshal([]byte(resultJSON), &m); err != nil {
		t.Fatal(err)
	}
	if m["is_first_run"] != true {
		t.Fatalf("expected is_first_run, got %v", m["is_first_run"])
	}
	if m["content_hash"] != "abc123" {
		t.Fatalf("expected content_hash, got %v", m["content_hash"])
	}
}
