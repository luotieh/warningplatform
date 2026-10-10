package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type reportSemanticModelFunc func(context.Context, evidence.SemanticCall) (string, error)

func (f reportSemanticModelFunc) Complete(ctx context.Context, call evidence.SemanticCall) (string, error) {
	return f(ctx, call)
}

func semanticReportFixture(t *testing.T, n int) (Services, EvidenceSnapshot) {
	t.Helper()
	svc := Services{Store: store.NewMemoryStore()}
	ctx := context.Background()
	_, err := svc.Store.CreateAsset(domain.Asset{ID: "asset-a", Address: "192.0.2.1", Status: 1})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	id := ""
	for index := 0; index < n; index++ {
		m := testHit(fmt.Sprintf("semantic-%d", index), base.Add(time.Duration(index)*time.Minute))
		m["protocol"], m["dst_port"] = "tcp", 80
		m["transaction_id"], m["session_id"] = fmt.Sprintf("tx-%d", index), "actual-session"
		body := fmt.Sprintf("username=alice&password=LOCAL_PASSWORD_%d", index)
		wire := fmt.Sprintf("POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
		m["app"] = map[string]any{"http_method": "POST", "http_host": "example.test"}
		m["raw_packet"] = map[string]any{"capture_truncated": false, "payload_hex": hex.EncodeToString([]byte(wire)), "tcp_seq": 100, "tcp_ack": 500, "response": map[string]any{"capture_truncated": false, "payload_hex": hex.EncodeToString([]byte(response)), "tcp_seq": 500, "tcp_ack": 100 + len(wire)}}
		r, err := svc.ProcessLyEvent(ctx, m)
		if err != nil {
			t.Fatal(err)
		}
		id = asString(r["deepsoc_event_id"])
	}
	if err := svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	snap, err := svc.EvidenceSnapshot(ctx, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	return svc, snap
}

func acceptedSemanticResponse(t *testing.T, call evidence.SemanticCall) string {
	t.Helper()
	var request struct {
		Tasks []evidence.SemanticTask `json:"tasks"`
	}
	if json.Unmarshal([]byte(call.Prompt), &request) != nil {
		t.Fatal("invalid semantic request")
	}
	items := []evidence.SemanticItem{}
	for _, task := range request.Tasks {
		item := evidence.SemanticItem{TaskID: task.ID, Judgement: "support", Strength: "weak", Explanation: "材料支持该行为结构，正常业务也是替代解释；未证明攻击成功", MaterialRefs: []string{}, FactRefs: []string{}, AdjudicationRefs: []string{}, Quotes: []evidence.SemanticQuote{}, Alternatives: []string{"正常业务行为"}, Gaps: []string{"缺少独立成功性证据"}}
		if task.Slot.ExplanationOnly {
			item.Strength = "none"
		}
		for _, m := range task.Materials {
			item.MaterialRefs = append(item.MaterialRefs, m.ID)
			runes := []rune(m.Text)
			quote := string(runes[:min(24, len(runes))])
			item.Quotes = append(item.Quotes, evidence.SemanticQuote{MaterialID: m.ID, Excerpt: quote})
			if m.AdjudicationID != "" {
				item.AdjudicationRefs = append(item.AdjudicationRefs, m.AdjudicationID)
			}
		}
		for _, f := range task.Facts {
			item.FactRefs = append(item.FactRefs, f.ID)
		}
		items = append(items, item)
	}
	raw, _ := json.Marshal(map[string]any{"items": items})
	return string(raw)
}

func TestSemanticReportSharesReadAndReusesIndependentCache(t *testing.T) {
	svc, snap := semanticReportFixture(t, 2)
	counter := &evidenceReadCounter{Store: svc.Store}
	svc.Store = counter
	calls := 0
	svc.SemanticModel = reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		calls++
		if !strings.Contains(call.Prompt, "LOCAL_PASSWORD_") {
			t.Fatal("raw material missing")
		}
		return acceptedSemanticResponse(t, call), nil
	})
	event := mustEvent(t, svc, snap.EventID)
	p, err := svc.prepareReportInput(context.Background(), event)
	if err != nil || p.Semantics.Status != "evaluated" || p.Semantics.Result == nil || len(p.Semantics.Result.Findings) == 0 || calls != 1 || counter.hitPages != 2 {
		t.Fatalf("shared pipeline failed: %v status=%s reason=%s calls=%d pages=%d", err, p.Semantics.Status, p.Semantics.Reason, calls, counter.hitPages)
	}
	if utf8.RuneCountInString(p.Context) > 6000 || !strings.Contains(p.Context, "semantic_evidence") {
		t.Fatal("shared report budget/projection missing")
	}
	for _, task := range p.Semantics.Result.Plan.Tasks {
		for _, m := range task.Materials {
			if m.Redacted {
				t.Fatal("raw field falsely marked redacted")
			}
		}
	}
	pages := counter.hitPages
	p, err = svc.prepareReportInput(context.Background(), event)
	if err != nil || !p.Evaluation.CacheHit || !p.Semantics.CacheHit || calls != 1 || counter.hitPages != pages {
		t.Fatalf("warm report recomputed: %v cache=%v calls=%d pages=%d", err, p.Semantics.CacheHit, calls, counter.hitPages)
	}
	d, err := svc.EvidenceInputDiagnostics(context.Background(), snap.EventID, snap.Version)
	if err != nil || d.Semantics == nil || !d.Semantics.CacheHit {
		t.Fatal("semantic diagnostics absent")
	}
	raw, _ := json.Marshal(d)
	if strings.Contains(string(raw), "LOCAL_PASSWORD_") {
		t.Fatal("raw payload leaked into diagnostics")
	}
}

func TestSemanticFailureRetriesWithoutChangingFacts(t *testing.T) {
	svc, snap := semanticReportFixture(t, 1)
	counter := &evidenceReadCounter{Store: svc.Store}
	svc.Store = counter
	fail := true
	calls := 0
	svc.SemanticModel = reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		calls++
		if fail {
			return "", errors.New("DRIVER_SECRET_IN_ERROR")
		}
		return acceptedSemanticResponse(t, call), nil
	})
	event := mustEvent(t, svc, snap.EventID)
	p, err := svc.prepareReportInput(context.Background(), event)
	if err != nil || p.Evaluation.Status != "evaluated" || p.Semantics.Status != "unavailable" || strings.Contains(p.Context, "DRIVER_SECRET_IN_ERROR") {
		t.Fatal("semantic failure destroyed facts or leaked error")
	}
	records, _ := svc.Store.AggregateRecords(context.Background(), "semantic_result", snap.EventID, 10)
	if len(records) != 0 {
		t.Fatal("transient model failure cached")
	}
	fail = false
	pages := counter.hitPages
	p, err = svc.prepareReportInput(context.Background(), event)
	if err != nil || p.Semantics.Status != "evaluated" || calls != 2 || counter.hitPages != pages {
		t.Fatal("semantic retry failed or reread hits")
	}
}

func TestSemanticBudgetAndReadOnlyPlanAreDistinctFromMissingMaterials(t *testing.T) {
	svc, snap := semanticReportFixture(t, 2)
	options := DefaultReportSemanticOptions()
	options.Config.MaxTasks = 1
	svc.ReportSemantics = &options
	calls := 0
	svc.SemanticModel = reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		calls++
		return acceptedSemanticResponse(t, call), nil
	})
	p, err := svc.prepareReportInput(context.Background(), mustEvent(t, svc, snap.EventID))
	if err != nil {
		t.Fatal(err)
	}
	summary := reportSemanticSummary(p.Semantics)
	if summary["budget_not_executed"].(int) == 0 || summary["missing_prerequisites"].(int) == 0 || p.Semantics.Result.Plan.Tasks[0].Slot.Key.ID != "S06" {
		t.Fatal("budget skips confused with missing inputs or priority lost")
	}
	guard := &noEvidenceWrites{Store: svc.Store}
	svc.Store = guard
	validation, err := svc.ValidateReportEvidence(context.Background(), snap.EventID)
	if err != nil || guard.writes != 0 || calls != 1 || validation.SemanticPlan["status"] != "planned" {
		t.Fatal("read-only validation invoked model or wrote data")
	}
}

func TestSemanticCacheRejectsCorruptedQuotesAndTracksModelVersion(t *testing.T) {
	svc, snap := semanticReportFixture(t, 1)
	calls := 0
	svc.SemanticModel = reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		calls++
		return acceptedSemanticResponse(t, call), nil
	})
	event := mustEvent(t, svc, snap.EventID)
	p, err := svc.prepareReportInput(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	p.Semantics.Result.Findings[0].Quotes[0].Excerpt = "invented quote not in source"
	if err := putRecord(context.Background(), svc.Store, "semantic_result", p.Semantics.ResultKey, snap.EventID, p.Semantics); err != nil {
		t.Fatal(err)
	}
	p, err = svc.prepareReportInput(context.Background(), event)
	if err != nil || p.Semantics.CacheHit || calls != 2 {
		t.Fatal("corrupt semantic cache trusted")
	}
	options := DefaultReportSemanticOptions()
	options.ModelVersion = "local-model-updated"
	svc.ReportSemantics = &options
	p, err = svc.prepareReportInput(context.Background(), event)
	if err != nil || p.Semantics.CacheHit || calls != 3 {
		t.Fatal("model revision retained stale interpretation")
	}
}

func TestAllReportKindsUseActualSemanticTransport(t *testing.T) {
	for _, kind := range []string{AnalysisKindInitial, AnalysisKindFinal, AnalysisKindManual} {
		t.Run(kind, func(t *testing.T) {
			svc, snap := semanticReportFixture(t, 1)
			semanticCalls, reportCalls := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("bad model request")
					return
				}
				system, user := "", ""
				for _, m := range body.Messages {
					if m.Role == "system" {
						system = m.Content
					}
					if m.Role == "user" {
						user = m.Content
					}
				}
				reply := "OK"
				if strings.Contains(system, "流量证据解释器") {
					semanticCalls++
					reply = acceptedSemanticResponse(t, evidence.SemanticCall{System: system, Prompt: user})
				} else if user != "health" {
					reportCalls++
					if !strings.Contains(user, `"kind":"semantic"`) || !strings.Contains(user, "正常业务也是替代解释") {
						t.Error("validated semantics absent from report prompt")
					}
					reply = acceptedReportResponse(t, user)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": reply}}}})
			}))
			defer server.Close()
			svc.LLM = &client.LLMClient{BaseURL: server.URL, Model: "local-fixture", HTTP: server.Client()}
			var err error
			switch kind {
			case AnalysisKindInitial:
				err = svc.RunAgentWorkflow(context.Background(), snap.EventID)
			case AnalysisKindFinal:
				_, _ = svc.Store.UpdateEvent(snap.EventID, map[string]any{"aggregation_closed": true})
				err = svc.RunFinalAnalysis(context.Background(), snap.EventID)
			case AnalysisKindManual:
				_, err = svc.RefreshAnalysis(context.Background(), snap.EventID)
			}
			if err != nil || semanticCalls != 1 || reportCalls != 1 {
				t.Fatalf("report kind %s failed: %v semantic=%d report=%d", kind, err, semanticCalls, reportCalls)
			}
		})
	}
}

func TestSemanticMaterialCacheBindingCorruptionRebuildsOnce(t *testing.T) {
	svc, snap := semanticReportFixture(t, 1)
	counter := &evidenceReadCounter{Store: svc.Store}
	svc.Store = counter
	svc.SemanticModel = reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		return acceptedSemanticResponse(t, call), nil
	})
	event := mustEvent(t, svc, snap.EventID)
	p, err := svc.prepareReportInput(context.Background(), event)
	if err != nil || p.Semantics.Result == nil {
		t.Fatal(err)
	}
	diag, err := svc.EvidenceInputDiagnostics(context.Background(), snap.EventID, snap.Version)
	if err != nil {
		t.Fatal(err)
	}
	key := digest([]any{diag.ResultKey, semanticAdapterVersion, evidence.SemanticRaw})
	record, ok, err := svc.Store.AggregateRecord(context.Background(), "semantic_materials", key)
	if err != nil || !ok {
		t.Fatal("missing material cache")
	}
	var cached cachedSemanticMaterials
	if json.Unmarshal(record.Value, &cached) != nil {
		t.Fatal("invalid fixture")
	}
	cached.Request.Subjects[0].Materials[0].Scope.AssetID = "unrelated-asset"
	if err := putRecord(context.Background(), svc.Store, "semantic_materials", key, snap.EventID, cached); err != nil {
		t.Fatal(err)
	}
	pages := counter.hitPages
	p, err = svc.prepareReportInput(context.Background(), event)
	if err != nil || p.Semantics.Status != "evaluated" || counter.hitPages != pages+2 || !strings.Contains(strings.Join(p.Semantics.Issues, ","), "binding_invalid_rebuilt") {
		t.Fatalf("material corruption recovery failed: %v %+v", err, p.Semantics)
	}
	p, err = svc.prepareReportInput(context.Background(), event)
	if err != nil || !p.Semantics.CacheHit || counter.hitPages != pages+2 {
		t.Fatal("repaired materials did not reuse cache")
	}
}

func TestSnapshotPromptCompressionPreservesJSONAndOmission(t *testing.T) {
	c := map[string]any{"snapshot_version": 1, "evidence_index": []any{map[string]any{"payload_text": strings.Repeat("X", 5000)}}, "algorithm_evidence": map[string]any{"status": "evaluated", "total_findings": 2, "omitted_findings": 0, "findings": []any{map[string]any{"fact_id": "F01"}, map[string]any{"fact_id": "F02"}}}, "semantic_evidence": map[string]any{"status": "evaluated", "total_findings": 1, "omitted_findings": 0, "findings": []any{map[string]any{"explanation": "已验证的模型解释", "quotes": []any{map[string]any{"excerpt": "实际报文"}}}}}}
	raw, _ := json.Marshal(c)
	compressed := fitSnapshotContextBudget(string(raw), 1000)
	var decoded map[string]any
	if json.Unmarshal([]byte(compressed), &decoded) != nil || !strings.Contains(compressed, "已验证的模型解释") || toInt(decoded["additional_samples_omitted_for_prompt"]) != 1 {
		t.Fatal("structured compression lost validation or omission")
	}
}

func TestSemanticDecodeDoesNotTreatHTTPPrefixAsDNSLabel(t *testing.T) {
	s := evidence.SemanticSubject{ID: "operation"}
	factory := func(s *evidence.SemanticSubject, kind, text, path string, p evidence.Provenance, complete bool) evidence.SemanticMaterial {
		return evidence.SemanticMaterial{ID: s.ID + ":" + kind, Kind: kind, Text: text}
	}
	addSemanticDecodeMaterials(&s, "Y29tbWFuZCBzdGFydA==.unrelated-body", nil, factory, evidence.Provenance{Complete: true})
	if len(s.Materials) != 0 {
		t.Fatal("unrelated HTTP suffix was ignored during decoding")
	}
	addSemanticDecodeMaterials(&s, "Y29tbWFuZCBzdGFydA==", nil, factory, evidence.Provenance{Complete: true})
	if len(s.Materials) != 4 || s.Materials[1].Text != "command start" {
		t.Fatal("actual single-layer decode missing")
	}
}
