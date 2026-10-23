package service

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

func v02Fact(id, key, source string) ReportEvidence {
	at := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	w := &evidence.Window{Start: at, End: at.Add(time.Hour)}
	scope := evidence.Scope{AssetID: "asset", EndpointID: "tcp://203.0.113.1:443", DeviceID: "node"}
	f := &evidence.Finding{FactID: evidence.FactID(key), Scope: scope, Window: w, Status: evidence.Observed, Eligibility: "eligible", Quality: "complete", SourceIDs: []string{source}, Measurements: evidence.Measurements{SampleCount: 16}}
	return ReportEvidence{ID: id, Kind: "fact", Name: key, FactID: f.FactID, Status: "observed", SourceIDs: f.SourceIDs, Scope: scope, Window: w, Finding: f, Result: "核验16条样本"}
}
func v02Semantic(id, key, source string) ReportEvidence {
	e := v02Fact(id, "", source)
	e.Kind = "semantic"
	e.Finding = nil
	e.Status = "support"
	e.Result = "已核验操作意图"
	e.Name = key
	p := strings.Split(key, "/")
	e.Semantic = &evidence.SemanticFinding{Slot: evidence.SlotKey{ID: p[0], Target: p[1], Subtype: p[2]}, Scope: e.Scope, SemanticItem: evidence.SemanticItem{Judgement: "support", Strength: "strong", MaterialRefs: []string{"material-" + source}, Quotes: []evidence.SemanticQuote{{MaterialID: "material-" + source, Excerpt: "actual operation"}}, Explanation: "已核验操作意图"}}
	return e
}
func v02Bundle(entries ...ReportEvidence) ReportEvidenceBundle {
	b := ReportEvidenceBundle{Entries: entries, Essence: &ReportEssenceBundle{Items: []ReportEssence{}}}
	for _, e := range entries {
		b.SelectedIDs = append(b.SelectedIDs, e.ID)
		b.Essence.Items = append(b.Essence.Items, ReportEssence{ID: e.ID, Name: e.Name, Summary: e.Result, Scope: e.Scope, Window: e.Window})
	}
	return b
}
func v02Candidate(t *testing.T, b ReportEvidenceBundle, kind string) ReportThreatScore {
	t.Helper()
	for _, c := range scoreReportThreats(b).Candidates {
		if c.Type == kind {
			return c
		}
	}
	t.Fatal("missing candidate")
	return ReportThreatScore{}
}
func TestReportV02HighScoresRequireActualIndependentEvidence(t *testing.T) {
	b := v02Bundle(v02Semantic("S1", "S01/c2.command_intent/", "command"), v02Fact("F1", "F_BEACON_PERIODIC", "timeline"))
	s := scoreReportThreats(b)
	if s.SelectedType != "c2_related" || s.Final != 92 {
		t.Fatalf("%+v", s)
	}
	if c := v02Candidate(t, b, "c2_related"); c.Cap != 94 || math.Abs(c.Z-2.5) > 1e-9 {
		t.Fatalf("%+v", c)
	}
	// The same packet is not independent corroboration of its own interpretation.
	b.Entries[1].SourceIDs = []string{"command"}
	b.Entries[1].Finding.SourceIDs = []string{"command"}
	if c := v02Candidate(t, b, "c2_related"); c.Cap != 79 || c.Base > 79 {
		t.Fatalf("self corroboration: %+v", c)
	}
	// Ordinary zero-payload observations never unlock a high-scoring type.
	weak := v02Fact("F2", "F_SMALL_PACKET", "ack")
	if s := scoreReportThreats(v02Bundle(weak)); s.HasEvidence {
		t.Fatalf("zero payload earned risk: %+v", s)
	}
}
func TestReportV02PermutationDuplicateAndMissingInvariance(t *testing.T) {
	command := v02Semantic("S1", "S01/c2.command_intent/", "command")
	period := v02Fact("F1", "F_BEACON_PERIODIC", "timeline")
	a := v02Candidate(t, v02Bundle(command, period), "c2_related")
	dup := period
	dup.ID = "F9"
	missing := v02Fact("F8", "F_FIXED_DAILY_WINDOW", "missing")
	missing.Finding.Status = evidence.Missing
	b := v02Candidate(t, v02Bundle(missing, dup, period, command), "c2_related")
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("changed by duplication/order/missing: %+v / %+v", a, b)
	}
	history := v02Fact("F3", "F_HIST_ASSET_IOC_RECURRENCE", "historical")
	c := v02Candidate(t, v02Bundle(command, period, history), "c2_related")
	if c.Base < a.Base {
		t.Fatal("independent positive lowered baseline")
	}
}
func TestReportV02TypeSpecificScores(t *testing.T) {
	tests := []struct {
		kind     string
		entries  []ReportEvidence
		min, max float64
	}{
		{"exfiltration_related", []ReportEvidence{v02Semantic("S1", "S07/exfil.sensitive_upload/", "upload"), v02Semantic("S2", "S08/exfil.chunk_sequence/", "chunks")}, 90, 91},
		{"botnet_related", []ReportEvidence{v02Semantic("S1", "S01/c2.command_intent/", "command"), v02Fact("F1", "F_TIME_COORDINATION", "coord")}, 94, 94},
		{"phishing_related", []ReportEvidence{v02Semantic("S1", "S05/phishing.deception/", "page"), v02Semantic("S2", "S06/phishing.credential_action/", "page"), v02Fact("F1", "F_REDIRECT_CHAIN", "chain")}, 86, 88},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			if test.kind == "botnet_related" {
				for j := range test.entries {
					test.entries[j].Scope.GroupID = "verified-group"
					if test.entries[j].Finding != nil {
						test.entries[j].Finding.Scope = test.entries[j].Scope
					}
				}
			}
			if test.kind == "exfiltration_related" || test.kind == "phishing_related" {
				last := len(test.entries) - 1
				test.entries[last].Dependencies = []evidence.Dependency{{Kind: "transfer_join", SourceIDs: []string{test.entries[0].SourceIDs[0], test.entries[last].SourceIDs[0]}}}
			}
			c := v02Candidate(t, v02Bundle(test.entries...), test.kind)
			if c.Base < test.min || c.Base > test.max {
				t.Fatalf("%+v", c)
			}
		})
	}
}
func TestReportV02PartialBindingAndUnknownKeys(t *testing.T) {
	e := v02Fact("F1", "F_BEACON_PERIODIC", "source")
	e.Finding.Quality = "partial"
	s := scoreReportThreats(v02Bundle(e))
	if s.Items[0].Reliability != .7 {
		t.Fatal(s.Items)
	}
	e.Scope.EndpointID = ""
	if s := scoreReportThreats(v02Bundle(e)); s.Items[0].X != 0 {
		t.Fatal("unbound endpoint scored")
	}
	unknown := v02Fact("F9", "F_NOT_IMPLEMENTED", "source")
	if s := scoreReportThreats(v02Bundle(unknown)); s.HasEvidence {
		t.Fatal("unknown rule scored")
	}
}
func TestReportV02BoundedModelAdjustmentAndProbabilityOwnership(t *testing.T) {
	b := v02Bundle(v02Semantic("S1", "S01/c2.command_intent/", "command"), v02Fact("F1", "F_BEACON_PERIODIC", "timeline"))
	context := v02Fact("O1", "", "application")
	context.Kind = "observation"
	context.Finding = nil
	context.Feature = "application_fields"
	context.Measurements = map[string]any{"host": "example.test"}
	b = v02Bundle(append(b.Entries, context)...)
	b.Scoring = scoreReportThreats(b)
	for _, tc := range []struct {
		name     string
		delta    int
		id, key  string
		accepted int
	}{
		{"valid", 2, "O1", "application_identity", 2},
		{"too large", 30, "O1", "application_identity", 0},
		{"double counting", 5, "F1", "application_identity", 0},
		{"unknown reference", 5, "D001", "application_identity", 0},
		{"unsupported context", 5, "O1", "personal_experience", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := 40
			a := ReportAssessment{ThreatType: "c2_related", Probability: &p, ModelAdjustment: &ReportModelAdjustment{Delta: tc.delta, EvidenceIDs: []string{tc.id}, ContextKey: tc.key, Reason: "observed application identity"}}
			if err := applyReportScoring(&a, b); err != nil {
				t.Fatal(err)
			}
			if a.Scoring.Adjustment.AcceptedDelta != tc.accepted || *a.Probability != min(94, 92+tc.accepted) {
				t.Fatalf("%+v", a)
			}
		})
	}
}
func TestReportV02KnowledgeAndRegisteredCoverage(t *testing.T) {
	b := v02Bundle(v02Fact("F1", "F_BEACON_PERIODIC", "timeline"))
	b.Scoring = scoreReportThreats(b)
	k := selectReportKnowledge(b)
	raw, _ := json.Marshal(k)
	if !strings.Contains(string(raw), "自动化") || !strings.Contains(string(raw), "F_BEACON_PERIODIC") {
		t.Fatal(string(raw))
	}
	if strings.Contains(string(raw), "族上限") || strings.Contains(string(raw), "## 分值算法摘要") {
		t.Fatal("whole cards leaked into context")
	}
	all := ""
	for name, text := range reportKnowledgeSources {
		all += text
		path := filepath.Join("../../../../KD", name+".md")
		if disk, err := os.ReadFile(path); err == nil && strings.ReplaceAll(string(disk), "\r\n", "\n") != text {
			t.Errorf("generated card drift: %s", name)
		}
	}
	for _, f := range evidence.Definitions() {
		if !strings.Contains(all, "`"+string(f.ID)+"`") {
			t.Errorf("missing fact: %s", f.ID)
		}
	}
	for _, s := range evidence.SemanticDefinitions() {
		sub := s.Key.Subtype
		if sub == "" {
			sub = "空"
		}
		if !strings.Contains(all, s.Key.ID+" / "+s.Key.Target+" / "+sub) {
			t.Errorf("missing semantic: %v", s.Key)
		}
	}
}
func TestReportV02StoredRenderAndLegacyIsolation(t *testing.T) {
	b := v02Bundle(v02Semantic("S1", "S01/c2.command_intent/", "command"), v02Fact("F1", "F_BEACON_PERIODIC", "timeline"))
	b.Pipeline = &EvidencePipelineAudit{Key: "audit-only"}
	b.Scoring = scoreReportThreats(b)
	a := ReportAssessment{Target: "malicious_activity", ThreatType: "c2_related", ProbabilityReason: "实际控制交互与周期通信相互印证。", Interpretations: []ReportInterpretation{{EvidenceID: "F1", Meaning: "已核验周期通信。"}, {EvidenceID: "S1", Meaning: "实际交互具有控制意图。"}}}
	if err := applyReportScoring(&a, b); err != nil {
		t.Fatal(err)
	}
	doc := ReportDocument{SchemaVersion: reportEvidenceVersion, LayoutVersion: reportFivePartLayout, Evidence: b, Assessment: a}
	before := renderReportMarkdown(doc)
	after := renderReportMarkdown(compactPipelineReport(doc))
	if before != after {
		t.Fatalf("stored render changed:\n%s\n%s", before, after)
	}
	if strings.Contains(before, "一期证据策略分") || strings.Contains(before, "audit-only") || strings.Contains(before, "sample_count") {
		t.Fatal(before)
	}
	if !strings.Contains(before, "92%") || !strings.Contains(before, "控制意图") {
		t.Fatal(before)
	}
}

// Optional replay consumes saved real production material, never fabricates facts
// or mutates the source event. Artifacts remain outside version control.
func TestReportV02RealMaterialReplay(t *testing.T) {
	dir := os.Getenv("REPORT_V02_REAL_LOG_DIR")
	if dir == "" {
		t.Skip("real replay material not configured")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "evidence-selection.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b ReportEvidenceBundle
	if err = json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Entries) > 0 && b.Entries[0].ID == "" {
		var saved struct {
			Entries []struct {
				Entry ReportEvidence `json:"entry"`
			} `json:"entries"`
		}
		if err = json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		b.Entries = nil
		for _, row := range saved.Entries {
			b.Entries = append(b.Entries, row.Entry)
		}
	}
	b = prepareReportV02Evidence(b)
	b.Scoring = scoreReportThreats(b)
	if !b.Scoring.HasEvidence {
		t.Fatal("real replay lost effective evidence")
	}
	prepared := preparedReportInput{}
	if original, err := os.ReadFile(filepath.Join(dir, "original-request.json")); err == nil {
		var request struct {
			Payload struct {
				Messages []struct{ Role, Content string } `json:"messages"`
			} `json:"payload"`
		}
		if json.Unmarshal(original, &request) == nil {
			for _, m := range request.Payload.Messages {
				if m.Role == "user" {
					var input struct {
						Overview ReportEventOverview `json:"event_overview"`
						Asset    string              `json:"asset_context"`
					}
					if json.Unmarshal([]byte(m.Content), &input) == nil {
						b.Overview = input.Overview
						prepared.AssetSection = input.Asset
					}
				}
			}
		}
	}
	prompt, err := evidenceReportPrompt(domain.Event{}, prepared, b, "")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, v any) {
		raw, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("v02-score.json", b.Scoring)
	write("v02-knowledge.json", selectReportKnowledge(b))
	write("v02-request.json", map[string]string{"system": evidenceReportSystemPrompt, "user": prompt})
	write("v02-coverage.json", map[string]any{"registered_facts": len(evidence.Definitions()), "registered_slots": len(evidence.SemanticDefinitions()), "catalog": reportV02CatalogAudit(b), "instances": b.Entries, "projection": b.Essence})
	t.Logf("real event: selected=%s baseline=%d input_estimate=%d items=%d", b.Scoring.SelectedType, b.Scoring.Final, estimateTokens(evidenceReportSystemPrompt+prompt), len(b.Essence.Items))
	if response, err := os.ReadFile(filepath.Join(dir, "v02-response.json")); err == nil {
		a, err := decodeReportAssessment(string(response), b)
		if err != nil {
			t.Fatal(err)
		}
		b.Scoring = a.Scoring
		doc := ReportDocument{SchemaVersion: reportEvidenceVersion, LayoutVersion: reportFivePartLayout, Evidence: b, Assessment: a}
		write("v02-assessment.json", a)
		if err := os.WriteFile(filepath.Join(dir, "v02-report.md"), []byte(renderReportMarkdown(doc)), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestReportV02ScopeAndUnprovenTransaction(t *testing.T) {
	command := v02Semantic("S1", "S01/c2.command_intent/", "command")
	period := v02Fact("F1", "F_BEACON_PERIODIC", "timeline")
	period.Scope.AssetID = "another-asset"
	if c := v02Candidate(t, v02Bundle(command, period), "c2_related"); c.Cap != 79 || len(c.Combinations) > 0 {
		t.Fatalf("mixed assets: %+v", c)
	}
	if c := v02Candidate(t, v02Bundle(v02Semantic("S1", "S07/exfil.sensitive_upload/", "upload"), v02Semantic("S2", "S08/exfil.chunk_sequence/", "chunks")), "exfiltration_related"); len(c.Combinations) > 0 || c.Cap != 79 {
		t.Fatalf("unverified transfer chain: %+v", c)
	}
}

func TestReportV02PromptIncludesCalculationRulesWithoutAudit(t *testing.T) {
	b := v02Bundle(v02Semantic("S1", "S01/c2.command_intent/", "command"), v02Fact("F1", "F_BEACON_PERIODIC", "timeline"))
	b.Scoring = scoreReportThreats(b)
	b.Pipeline = &EvidencePipelineAudit{Key: "audit-only-secret"}
	before, _ := json.Marshal(b.Scoring)
	prompt, err := evidenceReportPrompt(domain.Event{}, preparedReportInput{}, b, "")
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]json.RawMessage
	if err = json.Unmarshal([]byte(prompt), &input); err != nil {
		t.Fatal(err)
	}
	var score struct {
		Rules map[string]string `json:"calculation_rules"`
	}
	if err = json.Unmarshal(input["judgement_v02"], &score); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"effective_strength", "single_and_row", "deduplication", "combination", "counter", "baseline", "caps", "type_selection", "final_adjustment"} {
		if score.Rules[key] == "" {
			t.Errorf("missing rule %s", key)
		}
	}
	if !strings.Contains(score.Rules["single_and_row"], "35%") || !strings.Contains(score.Rules["combination"], "1.5") {
		t.Fatal("missing arithmetic explanation")
	}
	if _, ok := input["pipeline_audit"]; ok {
		t.Fatal("audit sent to model")
	}
	if strings.Contains(prompt, "audit-only-secret") || strings.Contains(prompt, "source_refs") {
		t.Fatal("audit source trace leaked")
	}
	after, _ := json.Marshal(b.Scoring)
	if string(before) != string(after) {
		t.Fatal("projection changed score")
	}
}

func TestReportV02CompleteOverviewAndReadableEvidence(t *testing.T) {
	b := v02Bundle(v02Semantic("S1", "S01/c2.command_intent/", "command"), v02Fact("F1", "F_BEACON_PERIODIC", "timeline"))
	b.Scoring = scoreReportThreats(b)
	for n := 0; n < 7; n++ {
		b.Overview.Tuples = append(b.Overview.Tuples, ReportOverviewTuple{Source: fmt.Sprintf("192.0.2.1:%d", 40000+n), Destination: "203.0.113.1:443", Protocol: "tcp", Hits: n + 1})
		b.Overview.IOCs = append(b.Overview.IOCs, ReportOverviewIOC{Value: fmt.Sprintf("ioc%d.example", n), Activity: strings.Repeat("完整情报", 80)})
	}
	prompt, err := evidenceReportPrompt(domain.Event{}, preparedReportInput{}, b, "")
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Overview struct {
			Tuples  []ReportOverviewTuple `json:"five_tuples"`
			IOCs    []ReportOverviewIOC   `json:"iocs"`
			Omitted int                   `json:"omitted_five_tuples"`
		} `json:"event_overview"`
	}
	if err = json.Unmarshal([]byte(prompt), &input); err != nil {
		t.Fatal(err)
	}
	if len(input.Overview.Tuples) != 7 || len(input.Overview.IOCs) != 7 || input.Overview.Omitted != 0 || input.Overview.IOCs[6].Activity != b.Overview.IOCs[6].Activity {
		t.Fatal("overview truncated")
	}
	a := ReportAssessment{ThreatType: "c2_related", Interpretations: []ReportInterpretation{{EvidenceID: "F1", Meaning: "核验样本呈周期通信。"}}}
	if err = applyReportScoring(&a, b); err != nil {
		t.Fatal(err)
	}
	doc := ReportDocument{Evidence: b, Assessment: a}
	body := renderReportV02(doc)
	key := strings.Split(strings.Split(body, "## 三、关键证据")[1], "## 四、风险分析")[0]
	if !strings.Contains(key, "**周期通信**：") || strings.Contains(key, "F1 ") || strings.Contains(key, "S1 ") {
		t.Fatal(key)
	}
	if !strings.Contains(body, "192.0.2.1:40006") || !strings.Contains(body, "ioc6.example") || strings.Contains(body, "另有") {
		t.Fatal("render truncated overview")
	}
	legacy := renderCompactEventOverview(doc)
	if !strings.Contains(legacy, "另有4组五元组") {
		t.Fatal("legacy changed")
	}
	_, err = evidenceReportPromptBudget(domain.Event{}, preparedReportInput{}, b, "", 10, 20, 100)
	if err == nil {
		t.Fatal("oversized full context must fail explicitly")
	}
}
