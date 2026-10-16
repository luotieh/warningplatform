package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestFormalWorkflowLogsActualInputAndPublishesProbability(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprint(broken), func(t *testing.T) {
			svc, snap := semanticReportFixture(t, 1)
			root := t.TempDir()
			if broken {
				root = filepath.Join(root, "file")
				_ = os.WriteFile(root, []byte("blocked"), 0600)
			}
			svc.ReportOptions = &config.ReportOptions{InputTokens: 20000, OutputTokens: 7000, ContextTokens: 30000, SafetyTokens: 3000, LogDir: root}
			svc.SemanticModel = reportSemanticModelFunc(func(_ context.Context, c evidence.SemanticCall) (string, error) {
				return acceptedSemanticResponse(t, c), nil
			})
			var actual map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload map[string]any
				_ = json.NewDecoder(r.Body).Decode(&payload)
				messages := payload["messages"].([]any)
				user := messages[len(messages)-1].(map[string]any)["content"].(string)
				reply := "OK"
				if user != "health" {
					actual = payload
					reply = acceptedReportResponse(t, user)
					var assessment ReportAssessment
					if err := json.Unmarshal([]byte(reply), &assessment); err != nil {
						t.Fatal(err)
					}
					// Material-gap wording is allowed; source binding validation must
					// still permit publication and probability synchronization.
					assessment.ProbabilityReason = "但无恶意内容、凭据或指令等直接证据"
					raw, _ := json.Marshal(assessment)
					reply = string(raw)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": reply}}}, "usage": map[string]any{"prompt_tokens": 1234, "completion_tokens": 456, "completion_tokens_details": map[string]any{"reasoning_tokens": 0}}})
			}))
			defer server.Close()
			svc.LLM = &client.LLMClient{BaseURL: server.URL, APIKey: "configuration-secret-never-log", Model: "fixture", HTTP: server.Client(), MaxTokens: 900}
			if err := svc.RunAgentWorkflow(context.Background(), snap.EventID); err != nil {
				t.Fatal(err)
			}
			if actual["max_tokens"] != float64(7000) || svc.LLM.MaxTokens != 900 || svc.LLM.ReportObserver != nil {
				t.Fatal("report configuration leaked", actual)
			}
			doc, err := svc.ReportDocument(context.Background(), snap.EventID, 0)
			if err != nil {
				t.Fatal(err)
			}
			if doc.Validation != pipelineReportValidation || doc.Assessment.ProbabilityReason != "但无恶意内容、凭据或指令等直接证据" {
				t.Fatal("removed checker still applied or result changed")
			}
			event := mustEvent(t, svc, snap.EventID)
			if doc.Assessment.Probability == nil || toInt(decodeEventContext(event.Context)["ai_probability"]) != *doc.Assessment.Probability {
				t.Fatal("list probability not synchronized")
			}
			if broken {
				return
			}
			paths, _ := filepath.Glob(filepath.Join(root, "*", "*", "*", "manifest.json"))
			if len(paths) != 1 {
				t.Fatal(paths)
			}
			dir := filepath.Dir(paths[0])
			for _, name := range []string{"evidence-before.json", "evidence-normalized.json", "evidence-essence.json", "evidence-essence-trace.json", "context-budget.json", "evidence-selection.json", "evidence-weights.json", "material-coverage.json", "llm-call-01-request.json", "llm-call-01-response.json", "probability-publication.json", "summary.md"} {
				raw, e := os.ReadFile(filepath.Join(dir, name))
				if e != nil {
					t.Fatal(name, e)
				}
				if strings.Contains(string(raw), svc.LLM.APIKey) {
					t.Fatal("configuration secret leaked", name)
				}
			}
			raw, _ := os.ReadFile(filepath.Join(dir, "llm-call-01-request.json"))
			var logged struct {
				Payload map[string]any `json:"payload"`
			}
			_ = json.Unmarshal(raw, &logged)
			x, _ := json.Marshal(logged.Payload)
			y, _ := json.Marshal(actual)
			if string(x) != string(y) {
				t.Fatal("logged prompt differs from actual request")
			}
			raw, _ = os.ReadFile(filepath.Join(dir, "llm-call-01-response.json"))
			if !strings.Contains(string(raw), `"prompt_tokens": 1234`) {
				t.Fatal("actual usage lost")
			}
		})
	}
}

func TestReportLogCompleteAndFailureIsolation(t *testing.T) {
	root := t.TempDir()
	_, r := beginReportLog(context.Background(), "../../asset/test", AnalysisKindManual, 3, config.ReportOptions{LogDir: root})
	r.write("evidence-before.json", map[string]any{"actual": "preserved"})
	r.finish(nil)
	raw, err := os.ReadFile(filepath.Join(r.dir, "manifest.json"))
	if err != nil || !strings.Contains(string(raw), `"status": "success"`) {
		t.Fatal(string(raw), err)
	}
	relative, err := filepath.Rel(root, r.dir)
	if err != nil || strings.HasPrefix(relative, "..") {
		t.Fatal("unsafe path")
	}
	file := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(file, []byte("not a directory"), 0600)
	_, bad := beginReportLog(context.Background(), "event", "manual", 3, config.ReportOptions{LogDir: file})
	bad.write("example.json", map[string]any{"x": 1})
	bad.finish(nil)
	if bad.errors == 0 {
		t.Fatal("write failure not observed")
	}
}

func TestReportPruneOnlyFinishedRuns(t *testing.T) {
	root := t.TempDir()
	_, finished := beginReportLog(context.Background(), "event", "manual", 1, config.ReportOptions{LogDir: root})
	finished.finish(nil)
	_, running := beginReportLog(context.Background(), "event", "manual", 2, config.ReportOptions{LogDir: root})
	n, err := PruneReportLogs(root, 30, time.Now().Add(31*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err = os.Stat(running.dir); err != nil {
		t.Fatal("running run removed", err)
	}
	if _, err = PruneReportLogs(t.TempDir(), 30, time.Now()); err == nil {
		t.Fatal("unmarked root allowed")
	}
}

func TestNewProbabilityRequiredButLegacyStillReadable(t *testing.T) {
	_, _, bundle := reportTestBundle(t)
	a := validReportAssessment(bundle)
	a.Probability = nil
	if err := validateReportAssessment(a, bundle); err != nil {
		t.Fatal("legacy validator changed", err)
	}
	raw, _ := json.Marshal(a)
	if _, err := decodeReportAssessment(string(raw), bundle); err == nil || err.Error() != "report_probability_required" {
		t.Fatal(err)
	}
	a = validPipelineAssessment(bundle)
	a.ProbabilityReason = ""
	raw, _ = json.Marshal(a)
	if _, err := decodeReportAssessment(string(raw), bundle); err == nil || err.Error() != "report_text_bounds" {
		t.Fatal("v2 report requires a source-bound probability explanation", err)
	}
	for _, n := range []int{0, 55, 101, -1} {
		a = validPipelineAssessment(bundle)
		a.Probability = &n
		raw, _ = json.Marshal(a)
		_, err := decodeReportAssessment(string(raw), bundle)
		if (n >= 0 && n <= 100) != (err == nil) {
			t.Fatalf("probability %d: %v", n, err)
		}
	}
}

type reportPublicationFailStore struct{ store.Store }

func (s reportPublicationFailStore) AggregationTransaction(ctx context.Context, key string, fn func(store.Store) error) error {
	return s.Store.AggregationTransaction(ctx, key, func(tx store.Store) error { return fn(reportMessageFailTx{tx}) })
}

type reportMessageFailTx struct{ store.Store }

func (s reportMessageFailTx) AddMessage(m domain.Message) (domain.Message, error) {
	return domain.Message{}, os.ErrPermission
}

func TestReportAtomicPublicationAndRollback(t *testing.T) {
	svc, event, bundle := reportTestBundle(t)
	a := validPipelineAssessment(bundle)
	old := 17
	_, _ = svc.Store.UpdateEvent(event.EventID, map[string]any{"context": `{"ai_probability":17,"business_marker":"keep"}`})
	doc := ReportDocument{SchemaVersion: reportEvidenceVersion, EventID: event.EventID, AnalysisVersion: 3, Kind: AnalysisKindManual, Assessment: a, Evidence: bundle}
	doc.Evidence.SnapshotVersion = 0
	doc.Markdown = renderReportMarkdown(doc)
	base := svc.Store
	svc.Store = reportPublicationFailStore{base}
	if _, err := svc.publishReportDocument(context.Background(), doc, 1, event); err == nil {
		t.Fatal("failed message did not abort publication")
	}
	got, _ := base.GetEvent(event.EventID)
	if toInt(decodeEventContext(got.Context)["ai_probability"]) != old || len(base.ListSummaries(event.EventID)) != 0 {
		t.Fatal("partial publication", got)
	}
	svc.Store = base
	sm, err := svc.publishReportDocument(context.Background(), doc, 1, event)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = base.GetEvent(event.EventID)
	c := decodeEventContext(got.Context)
	if toInt(c["ai_probability"]) != *a.Probability || toInt(c["report_summary_id"]) != int(sm.ID) || c["business_marker"] != "keep" {
		t.Fatal(c)
	}
	if _, err = svc.publishReportDocument(context.Background(), doc, 1, event); err == nil {
		t.Fatal("older/equal version overwrote report")
	}
}
