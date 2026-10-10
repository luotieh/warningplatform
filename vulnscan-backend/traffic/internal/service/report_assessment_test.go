package service

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestReportPromptBudgetPreservesAuthoritativeEntries(t *testing.T) {
	_, event, bundle := reportTestBundle(t)
	event.EventName = strings.Repeat("长标题", 10000)
	p := preparedReportInput{Context: `{"auxiliary":"` + strings.Repeat("辅助材料", 20000) + `"}`, AssetSection: strings.Repeat("资产", 20000)}
	prompt, err := evidenceReportPrompt(event, p, bundle, strings.Repeat("对话", 20000))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Entries        []ReportEvidence `json:"selected_evidence"`
		ContextOmitted bool             `json:"context_omitted_for_budget"`
	}
	if json.Unmarshal([]byte(prompt), &input) != nil || !input.ContextOmitted || len(input.Entries) != len(bundle.SelectedIDs) {
		t.Fatal("budget reduction removed authoritative entries or omission marker")
	}
	if estimateTokens(prompt) > eventDataBudgetTokens || estimateTokens(evidenceReportSystemPrompt+prompt) > promptBudgetTokens {
		t.Fatal("prompt budget exceeded")
	}
}

func TestReportChecksDistinguishNegationFromSuccessClaim(t *testing.T) {
	_, _, bundle := reportTestBundle(t)
	for _, text := range []string{"未证明攻击成功", "没有证据证明攻击成功", "不能排除C2"} {
		a := validReportAssessment(bundle)
		a.Gaps = []string{text}
		if err := validateReportAssessment(a, bundle); err != nil {
			t.Fatalf("valid qualification %s: %v", text, err)
		}
	}
	a := validReportAssessment(bundle)
	a.Gaps = []string{"未证明攻击成功，但是确认攻击成功"}
	if err := validateReportAssessment(a, bundle); err == nil {
		t.Fatal("negation concealed a second success claim")
	}
}

func TestInvalidModelReportFailsWithoutPublishingSummary(t *testing.T) {
	svc, snap := semanticReportFixture(t, 1)
	svc.SemanticModel = reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		return acceptedSemanticResponse(t, call), nil
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid request")
			return
		}
		reply := "OK"
		for _, m := range request.Messages {
			if m.Role == "user" && m.Content != "health" {
				reply = `{"target":"malicious_activity","probability":99}`
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": reply}}}})
	}))
	defer server.Close()
	svc.LLM = &client.LLMClient{BaseURL: server.URL, Model: "local-fixture", HTTP: server.Client()}
	if err := svc.RunAgentWorkflow(context.Background(), snap.EventID); err == nil {
		t.Fatal("invalid report was accepted")
	}
	if len(svc.Store.ListSummaries(snap.EventID)) != 0 {
		t.Fatal("invalid report published a summary")
	}
	event := mustEvent(t, svc, snap.EventID)
	if event.EventStatus != "failed" {
		t.Fatalf("unexpected failure state: %s", event.EventStatus)
	}
	record, exists, err := svc.Store.AggregateRecord(context.Background(), "report_validation_failure", snapshotKey(snap.EventID, snap.Version))
	if err != nil || !exists || !strings.Contains(string(record.Value), "report_threat_type_invalid") {
		t.Fatal("validation diagnostic missing")
	}
}

func validReportAssessment(b ReportEvidenceBundle) ReportAssessment {
	a := ReportAssessment{Target: "malicious_activity", Verdict: "suspicious", Stage: "contact", ProbabilityReason: "通联事实构成核查依据，具体行为需要结合业务背景复核", Supporting: []ReportReason{}, Opposing: []ReportReason{}, Alternatives: []ReportReason{}, Interpretations: []ReportInterpretation{}, Gaps: []string{"补充业务归属与主机侧独立证据"}, Actions: []ReportAction{}}
	a.ThreatType = "suspicious_contact"
	allowed := map[string]bool{}
	for _, id := range b.SelectedIDs {
		allowed[id] = true
		a.Interpretations = append(a.Interpretations, ReportInterpretation{id, "为当前通信行为提供核验依据"})
	}
	for _, e := range b.Entries {
		if allowed[e.ID] && (e.Kind == "observation" || e.Kind == "fact" && e.Status == "observed") {
			a.Supporting = append(a.Supporting, ReportReason{[]string{e.ID}, "已核验的行为记录支撑进一步调查"})
			a.Actions = append(a.Actions, ReportAction{[]string{e.ID}, "核查该资产的业务关联", "区分正常业务与异常通信"})
			probability := 35
			a.Probability = &probability
			break
		}
	}
	if a.Probability == nil {
		a.Verdict = "insufficient"
		a.Stage = "undetermined"
	}
	return a
}

func acceptedReportResponse(t *testing.T, prompt string) string {
	t.Helper()
	var request struct {
		Entries []ReportEvidence `json:"selected_evidence"`
	}
	if json.Unmarshal([]byte(prompt), &request) != nil {
		t.Fatal("invalid report JSON")
	}
	b := ReportEvidenceBundle{Entries: request.Entries, SelectedIDs: []string{}}
	for _, e := range b.Entries {
		b.SelectedIDs = append(b.SelectedIDs, e.ID)
	}
	raw, _ := json.Marshal(validReportAssessment(b))
	return string(raw)
}

func reportTestBundle(t *testing.T) (Services, domain.Event, ReportEvidenceBundle) {
	t.Helper()
	svc, snap := semanticReportFixture(t, 2)
	p, err := svc.prepareReportInputMode(context.Background(), mustEvent(t, svc, snap.EventID), false)
	if err != nil {
		t.Fatal(err)
	}
	return svc, mustEvent(t, svc, snap.EventID), p.Evidence
}

func TestReportUsesCompleteFindingsNotCompressedProjection(t *testing.T) {
	_, _, b := reportTestBundle(t)
	if len(b.FactChecks) != 59 || b.FactCounts["missing"]+b.FactCounts["observed"]+b.FactCounts["not_observed"] != 59 {
		t.Fatal("full checks lost before selection")
	}
	observed := false
	for _, e := range b.Entries {
		if e.FactID == "F_CRED_POST_STRUCTURE" {
			observed = true
			if e.Finding == nil || len(e.SourceIDs) == 0 || !strings.Contains(e.Result, "凭据字段POST请求数=2") {
				t.Fatal("actual measurements/provenance missing")
			}
		}
		if e.Status == "missing" {
			t.Fatal("missing rules promoted to evidence")
		}
	}
	if !observed {
		t.Fatal("positive fact not in authoritative evidence list")
	}
	raw, _ := json.Marshal(b)
	var copy ReportEvidenceBundle
	json.Unmarshal(raw, &copy)
	if len(copy.FactChecks) != len(b.FactChecks) || len(copy.SelectedIDs) > 12 {
		t.Fatal("journal/projection contract failed")
	}
}

func TestReportRejectsUnboundOverclaimsAndChangedNumbers(t *testing.T) {
	_, _, b := reportTestBundle(t)
	for _, tc := range []struct {
		name, want string
		mutate     func(*ReportAssessment)
	}{
		{"unknown evidence", "reference", func(a *ReportAssessment) { a.Supporting[0].EvidenceIDs = []string{"E999"} }},
		{"changed count", "numbers", func(a *ReportAssessment) { a.Interpretations[0].Meaning = "已发生999次通联" }},
		{"missing as absence", "overclaim", func(a *ReportAssessment) { a.ProbabilityReason = "已经排除了周期性通信" }},
		{"C2 exclusion", "overclaim", func(a *ReportAssessment) { a.ProbabilityReason = "证据已排除C2" }},
		{"host compromised", "overclaim", func(a *ReportAssessment) { a.ProbabilityReason = "已失陷并植入恶意载荷" }},
		{"duplicate contribution", "duplicate", func(a *ReportAssessment) { a.Supporting = append(a.Supporting, a.Supporting[0]) }},
		{"no probability basis", "without_evidence", func(a *ReportAssessment) { a.Supporting = []ReportReason{} }},
		{"unbound action", "action", func(a *ReportAssessment) { a.Actions[0].EvidenceIDs = []string{"E999"} }},
		{"unbound threat type", "threat_type_without_evidence", func(a *ReportAssessment) { a.ThreatType = "botnet_related" }},
		{"intelligence-only malicious", "without_behavior", func(a *ReportAssessment) { a.Verdict = "likely_malicious" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := validReportAssessment(b)
			tc.mutate(&a)
			err := validateReportAssessment(a, b)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid judgement accepted or wrong reason: %v", err)
			}
		})
	}
	a := validReportAssessment(b)
	raw, _ := json.Marshal(a)
	if _, err := decodeReportAssessment(string(raw), b); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeReportAssessment(strings.Replace(string(raw), `"target":"malicious_activity"`, `"target":"malicious_activity","target":"malicious_activity"`, 1), b); err == nil {
		t.Fatal("duplicate JSON keys accepted")
	}
	if _, err := decodeReportAssessment(string(raw)+` {}`, b); err == nil {
		t.Fatal("extra JSON root accepted")
	}
}

func TestReportRejectsFactSemanticDoubleContribution(t *testing.T) {
	b := ReportEvidenceBundle{Entries: []ReportEvidence{{ID: "E001", Kind: "fact", Status: "observed", FactID: "F_CRED_POST_STRUCTURE", Family: "fact:credential"}, {ID: "E002", Kind: "semantic", Status: "support", Family: "semantic:credential", RelatedFactIDs: []string{"F_CRED_POST_STRUCTURE"}, Semantic: &evidence.SemanticFinding{SemanticItem: evidence.SemanticItem{Judgement: "support"}}}}, SelectedIDs: []string{"E001", "E002"}}
	a := validReportAssessment(b)
	a.Supporting = append(a.Supporting, ReportReason{[]string{"E002"}, "语义解释对应同一提交行为"})
	if err := validateReportAssessment(a, b); err == nil || !strings.Contains(err.Error(), "double_count") {
		t.Fatalf("same fact counted twice: %v", err)
	}
}

func TestReportDocumentPinnedAndDOCXHasAuthoritativeAppendix(t *testing.T) {
	svc, event, b := reportTestBundle(t)
	document := ReportDocument{SchemaVersion: reportEvidenceVersion, EventID: event.EventID, Title: "证据报告", AnalysisVersion: 1, Kind: AnalysisKindInitial, CreatedAt: time.Now(), Evidence: b, Assessment: validReportAssessment(b), Validation: "references_and_facts_validated"}
	document.Markdown = renderReportMarkdown(document)
	summary, err := svc.saveReportDocument(context.Background(), document, 1)
	if err != nil {
		t.Fatal(err)
	}
	// A later event state or legacy summary must not replace this report's input.
	svc.Store.UpdateEvent(event.EventID, map[string]any{"context": `{"occurrence_count":9999}`})
	svc.Store.AddSummary(domain.Summary{EventID: event.EventID, Version: 3, Kind: AnalysisKindManual, EventSummary: "旧式文本"})
	pinned, err := svc.ReportDocument(context.Background(), event.EventID, summary.ID)
	if err != nil || pinned.SummaryID != summary.ID || pinned.Markdown != document.Markdown {
		t.Fatal("historical report changed", err)
	}
	if _, err := svc.ReportDocument(context.Background(), "unrelated-event", summary.ID); err == nil {
		t.Fatal("cross-event summary accepted")
	}
	data, err := ExportEvidenceReportDOCX(pinned)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal("not a genuine DOCX", err)
	}
	found := false
	for _, file := range zr.File {
		if strings.HasSuffix(file.Name, ".xml") {
			r, _ := file.Open()
			raw, _ := io.ReadAll(r)
			r.Close()
			decoder := xml.NewDecoder(bytes.NewReader(raw))
			for {
				_, err = decoder.Token()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("invalid OOXML %s: %v", file.Name, err)
				}
			}
			if file.Name == "word/document.xml" {
				found = true
				for _, want := range []string{"事实证据与研判意义", "完整事实检查清单", "F_CRED_POST_STRUCTURE", "凭据字段POST请求数=2", "tblHeader", "cantSplit", "11906", "E8EEF6"} {
					if !bytes.Contains(raw, []byte(want)) {
						t.Errorf("DOCX missing %s", want)
					}
				}
				if bytes.Contains(raw, []byte("Invalid token")) {
					t.Fatal("run logs included")
				}
			}
		}
	}
	if !found {
		t.Fatal("DOCX document missing")
	}
}

type failingReportTransaction struct {
	store.Store
	failSummary bool
}

func (s failingReportTransaction) AggregationTransaction(ctx context.Context, key string, fn func(store.Store) error) error {
	return s.Store.AggregationTransaction(ctx, key, func(tx store.Store) error { return fn(failingReportTransaction{Store: tx, failSummary: s.failSummary}) })
}
func (s failingReportTransaction) AddSummary(sm domain.Summary) (domain.Summary, error) {
	if s.failSummary {
		return domain.Summary{}, fmt.Errorf("injected summary failure")
	}
	return s.Store.AddSummary(sm)
}
func (s failingReportTransaction) PutAggregateRecord(ctx context.Context, r store.AggregateRecord) error {
	if r.Kind == "report_document" {
		return fmt.Errorf("injected evidence document failure")
	}
	return s.Store.PutAggregateRecord(ctx, r)
}

func TestReportPublicationAtomicAndJournalImmutable(t *testing.T) {
	for _, failSummary := range []bool{false, true} {
		svc, event, b := reportTestBundle(t)
		doc := ReportDocument{SchemaVersion: reportEvidenceVersion, EventID: event.EventID, AnalysisVersion: 1, Kind: AnalysisKindInitial, Evidence: b, Assessment: validReportAssessment(b)}
		doc.Markdown = renderReportMarkdown(doc)
		base := svc.Store
		svc.Store = failingReportTransaction{Store: base, failSummary: failSummary}
		if _, err := svc.saveReportDocument(context.Background(), doc, 1); err == nil {
			t.Fatal("injected failure ignored")
		}
		if len(base.ListSummaries(event.EventID)) != 0 {
			t.Fatal("unbound summary survived transaction rollback")
		}
		records, err := base.AggregateRecords(context.Background(), "report_document", event.EventID, 10)
		if err != nil || len(records) != 0 {
			t.Fatal("document survived transaction rollback")
		}
		svc.Store = base
		summary, err := svc.saveReportDocument(context.Background(), doc, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err = putRecord(context.Background(), base, "report_document", reportDocumentKey(event.EventID, summary.ID), event.EventID, doc); err == nil {
			t.Fatal("immutable report overwritten")
		}
		other, err := svc.saveReportDocument(context.Background(), doc, 1)
		if err != nil || other.ID == summary.ID {
			t.Fatal("separate summaries share journal identity")
		}
		if _, err = svc.ReportDocument(context.Background(), event.EventID, summary.ID); err != nil {
			t.Fatal("retry damaged original report", err)
		}
	}
}

func TestProvidedPhishingReportMistakesAreRejected(t *testing.T) {
	// Regression statements taken from the supplied report. This tests its
	// demonstrated failure modes, not an invented reconstruction of packets.
	_, _, b := reportTestBundle(t)
	for _, text := range []string{"58/59项发现未产出", "证据排除了beacon周期性与大体量外传", "共2包约1448字节，证明已建立恶意会话"} {
		a := validReportAssessment(b)
		a.ProbabilityReason = text
		if err := validateReportAssessment(a, b); err == nil {
			t.Fatalf("supplied report regression accepted: %s", text)
		}
	}
}
