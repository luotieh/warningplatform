package service

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Explicit opt-in replay of an exported production run. No production database
// is written. Historical metrics embedded in old Result strings are decoded
// only here to migrate the old audit format, never in the production adapter.
func TestReportEssenceRealMaterialReplay(t *testing.T) {
	dir := os.Getenv("REPORT_REAL_LOG_DIR")
	if dir == "" {
		t.Skip("exported real event material not supplied")
	}
	output := os.Getenv("REPORT_REAL_OUTPUT_DIR")
	if output == "" {
		t.Fatal("output directory required")
	}
	read := func(name string, value any) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, value); err != nil {
			t.Fatal(err)
		}
	}
	var materials struct {
		Snapshot EvidenceSnapshot `json:"snapshot"`
		History  ReportHistory    `json:"history"`
	}
	read("snapshot-materials.json", &materials)
	var before struct {
		Facts     SnapshotFactEvaluation   `json:"facts"`
		Semantics ReportSemanticEvaluation `json:"semantics"`
	}
	read("evidence-before.json", &before)
	for n := range before.Facts.Manifest.ReportPractical {
		e := &before.Facts.Manifest.ReportPractical[n]
		e.Feature = strings.TrimPrefix(e.Family, "report_practical:")
		marker := "实际结果="
		start := strings.Index(e.Result, marker)
		if start < 0 {
			t.Fatal("old measured result missing", e.Family)
		}
		if err := json.NewDecoder(strings.NewReader(e.Result[start+len(marker):])).Decode(&e.Measurements); err != nil {
			t.Fatal(err)
		}
		for _, check := range before.Facts.Manifest.ReportPracticalChecks {
			if check.Feature == e.Feature && check.Scope == e.Scope {
				e.Measurements["used_records"] = check.Used
				e.Measurements["excluded_records"] = check.Excluded
			}
		}
	}
	snap := materials.Snapshot
	event := domain.Event{EventID: snap.EventID, EventName: "真实事件材料回放", Context: string(mustReplayJSON(t, snap.Context))}
	assetSection := ""
	if path := os.Getenv("REPORT_REAL_REQUEST_FILE"); path != "" {
		var request struct {
			Payload struct {
				Messages []struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"messages"`
			} `json:"payload"`
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(raw, &request); e != nil {
			t.Fatal(e)
		}
		for _, message := range request.Payload.Messages {
			if message.Role == "user" {
				var input struct {
					Asset string `json:"asset_registry"`
					Event struct {
						Title string `json:"title"`
					} `json:"event"`
				}
				if e = json.Unmarshal([]byte(message.Content), &input); e != nil {
					t.Fatal(e)
				}
				assetSection = normalizeReportAssetSection(input.Asset)
				if input.Event.Title != "" {
					event.EventName = input.Event.Title
				}
			}
		}
	}
	b := buildReportEvidence(event, snap, before.Facts, before.Semantics, materials.History)
	p := preparedReportInput{AssetSection: assetSection, Evidence: b, Evaluation: before.Facts, Semantics: before.Semantics}
	ctx, audit := beginReportLog(context.Background(), event.EventID, "real_material_replay", 1, config.ReportOptions{LogDir: output, InputTokens: 20000, OutputTokens: 6000})
	audit.prepared(p)
	prompt, err := evidenceReportPrompt(event, p, b, "")
	if err != nil {
		audit.finish(err)
		t.Fatal(err)
	}
	audit.write("llm-prepared.json", map[string]any{"system": evidenceReportSystemPrompt, "user": prompt})
	audit.write("context-budget.json", map[string]any{"user_bytes": len(prompt), "user_estimated_tokens": estimateTokens(prompt), "system_estimated_tokens": estimateTokens(evidenceReportSystemPrompt), "full_estimated_tokens": estimateTokens(evidenceReportSystemPrompt+prompt) + 12, "estimate_method": "CJK estimator, not provider measured tokens", "input_limit": 20000, "output_reserved_tokens": 6000, "core_evidence_omitted": false})
	audit.write("replay-metadata.json", map[string]any{"source_run": filepath.Base(dir), "event_id": snap.EventID, "snapshot_version": snap.Version, "original_fact_results_reused": true, "original_validated_semantics_reused": true, "database": "isolated memory store", "production_database_written": false})
	t.Logf("event=%s snapshot=%d original_entries=%d essence=%d bytes=%d estimated_tokens=%d logs=%s", snap.EventID, snap.Version, len(b.Entries), len(b.Essence.Items), len(prompt), estimateTokens(prompt), audit.dir)
	for _, e := range b.Entries {
		for _, id := range e.SourceIDs {
			if len(id) > 20 && strings.Contains(prompt, id) {
				t.Fatal("source identity leaked", e.ID)
			}
		}
	}
	base := os.Getenv("REPORT_REAL_MODEL_PROXY")
	previous := os.Getenv("REPORT_REAL_ACCEPTED_RUN")
	if base == "" && previous == "" {
		audit.finish(nil)
		return
	}
	llm := client.LLMClient{BaseURL: base, Model: "production-model-through-private-proxy", HTTP: &http.Client{Timeout: 12 * time.Minute}, MaxTokens: 6000, ReportThinkingDisabled: true, ReportObserver: audit.observe}
	var reply string
	if previous != "" {
		var sent struct {
			System string `json:"system"`
			User   string `json:"user"`
		}
		raw, e := os.ReadFile(filepath.Join(previous, "llm-prepared.json"))
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(raw, &sent); e != nil {
			t.Fatal(e)
		}
		if sent.System != evidenceReportSystemPrompt || sent.User != prompt {
			t.Fatal("recorded model input differs; new actual model call required")
		}
		raw, e = os.ReadFile(filepath.Join(previous, "llm-assessment.json"))
		if e != nil {
			t.Fatal(e)
		}
		reply = string(raw)
		audit.write("actual-response-reuse.json", map[string]any{"source_run": previous, "identical_actual_model_input": true, "new_model_call": false, "reason": "renderer-only validation with the unchanged actual model answer"})
	} else {
		completion, e := llm.CompleteReport(ctx, evidenceReportSystemPrompt, prompt)
		if e != nil {
			audit.finish(e)
			t.Fatal(e)
		}
		reply = completion.Reply
	}
	a, err := decodeReportAssessment(reply, b)
	if err != nil {
		audit.finish(err)
		t.Fatal(err)
	}
	audit.write("llm-assessment.json", a)
	svc := Services{Store: store.NewMemoryStore()}
	if _, err = svc.Store.CreateEvent(event); err != nil {
		t.Fatal(err)
	}
	if err = putRecord(ctx, svc.Store, "segment", event.EventID, event.EventID, EventSegment{EventID: event.EventID, CanonicalID: event.EventID, Version: snap.Version, Count: snap.Count}); err != nil {
		t.Fatal(err)
	}
	doc := ReportDocument{AssetSection: assetSection, SchemaVersion: reportEvidenceVersion, EventID: event.EventID, Title: event.EventName, AnalysisVersion: 1, Kind: AnalysisKindManual, CreatedAt: time.Now().UTC(), Evidence: b, Assessment: a, Validation: "json_and_probability_parsed_only", BuildRevision: ReportBuildRevision}
	doc.Markdown = renderReportMarkdown(doc)
	summary, err := svc.publishReportDocument(ctx, doc, 1, event)
	if err != nil {
		audit.finish(err)
		t.Fatal(err)
	}
	saved, err := svc.ReportDocument(ctx, event.EventID, summary.ID)
	if err != nil {
		t.Fatal(err)
	}
	updated, _ := svc.Store.GetEvent(event.EventID)
	probability := decodeEventContext(updated.Context)["ai_probability"]
	if toInt(probability) != *a.Probability {
		t.Fatal("probability not synchronized")
	}
	audit.write("probability-publication.json", map[string]any{"summary_id": summary.ID, "probability": a.Probability, "event_probability": probability, "database": "isolated memory store", "published": true})
	audit.write("report-document.json", saved)
	if err = os.WriteFile(filepath.Join(audit.dir, "report.md"), []byte(saved.Markdown), 0600); err != nil {
		t.Fatal(err)
	}
	audit.finish(nil)
	t.Logf("actual_model_probability=%d local_report_id=%d event_probability=%v", *a.Probability, summary.ID, probability)
}

func mustReplayJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
