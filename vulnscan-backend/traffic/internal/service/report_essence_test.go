package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

func essenceFixture() ReportEvidenceBundle {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	w := &evidence.Window{Start: at, End: at.Add(time.Hour)}
	scope := evidence.Scope{AssetID: "asset-A", DeviceID: "device", EndpointID: "tcp://192.0.2.1:443"}
	cv, period := 0.03, 60.0
	f := evidence.Finding{FactID: evidence.BeaconPeriodic, Status: evidence.Observed, Eligibility: "eligible", SnapshotVersion: 4, Scope: scope, Window: w, SourceIDs: []string{"ly-private-001", "ly-private-002"}, Measurements: evidence.Measurements{SampleCount: 8, IntervalCV: &cv, MedianIntervalSeconds: &period}}
	return ReportEvidenceBundle{SelectedIDs: []string{"E001", "E002", "E003", "E004"}, Entries: []ReportEvidence{
		{ID: "E001", Name: "周期通信", Status: "observed", FactID: f.FactID, Scope: scope, Window: w, SourceIDs: f.SourceIDs, Finding: &f},
		{ID: "E002", Feature: "time_distribution", Name: "间隔分布", Status: "observed", Scope: scope, Window: w, SourceIDs: []string{"ly-private-002", "ly-private-001"}, Measurements: map[string]any{"used_records": 8, "平均间隔秒": 60, "间隔变异系数": 0.03, "间隔样本数": 7}},
		{ID: "E003", Scope: scope, Window: w, SourceIDs: f.SourceIDs, Semantic: &evidence.SemanticFinding{Scope: scope, SnapshotVersion: 4, Window: evidence.AnalysisWindow{Start: w.Start, End: w.End}, SemanticItem: evidence.SemanticItem{Judgement: "support", Explanation: "通信规律稳定，反映重复交互", FactRefs: []string{string(f.FactID)}}}},
		{ID: "E004", Feature: "history_association_transport", Status: "observed", Name: "历史传输", Scope: scope, Measurements: map[string]any{"IOC": "192.0.2.1", "实际传输接触事件数": 3, "事件首记录日期次数": map[string]int{"2026-10-01": 2, "2026-10-03": 1}}},
	}}
}

func TestEssenceMergesSamePopulationAndKeepsMeasurements(t *testing.T) {
	b := essenceFixture()
	e := buildReportEssence(b)
	if len(e.Items) != 2 || len(e.Items[0].Details) != 3 || len(e.Items[0].Interpretations) != 1 {
		t.Fatalf("merge result %+v", e)
	}
	if e.Trace[1].EvidenceID != "E001" || e.Trace[1].Reason != "merged_same_interval_population" {
		t.Fatal(e.Trace)
	}
	b.Essence = &e
	policy := reportWeightPolicy(b)
	weights := policy["enhanced_temporal"].([]map[string]any)
	if len(weights) != 1 || weights[0]["evidence_id"] != "E001" || weights[0]["relative_influence"] != 1.25 {
		t.Fatal(policy)
	}
	raw, _ := json.Marshal(e.Details)
	if !strings.Contains(string(raw), "0.03") || !strings.Contains(string(raw), "60") {
		t.Fatal("measurements lost")
	}
}

func TestEssenceDoesNotMergeDifferentScopeWindowOrPopulation(t *testing.T) {
	for _, change := range []func(*ReportEvidence){func(e *ReportEvidence) { e.Scope.AssetID = "asset-B" }, func(e *ReportEvidence) { w := *e.Window; w.End = w.End.Add(time.Second); e.Window = &w }, func(e *ReportEvidence) { e.SourceIDs = []string{"another-record"} }} {
		b := essenceFixture()
		change(&b.Entries[1])
		e := buildReportEssence(b)
		if e.Trace[1].Reason != "retained" {
			t.Fatal("independent observations merged", e.Trace)
		}
	}
	b := essenceFixture()
	b.Entries[2].Semantic.SnapshotVersion = 99
	e := buildReportEssence(b)
	if len(e.Items[0].Interpretations) != 0 {
		t.Fatal("different snapshot attached")
	}
}

func TestEssencePromptRenderingAndTraceAgree(t *testing.T) {
	b := essenceFixture()
	e := buildReportEssence(b)
	b.Essence = &e
	prompt, err := evidenceReportPrompt(domain.Event{}, preparedReportInput{AssetSection: "资产A"}, b, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"ly-private-001", "source_catalog", "source_sets", "gap_reasons", "rule_parameters"} {
		if strings.Contains(prompt, bad) {
			t.Fatal("audit metadata leaked", bad)
		}
	}
	if len(e.Trace[0].SourceIDs) != 2 {
		t.Fatal("full trace lost")
	}
	a := ReportAssessment{Interpretations: []ReportInterpretation{{EvidenceID: "E001", Meaning: "模型错误地改写成999秒"}}, Risks: []ReportRisk{{Exposure: "持续连接999天", EvidenceIDs: []string{"E001"}, Impact: "若通联被滥用，将影响资产数据安全"}}}
	body := renderReportMarkdown(ReportDocument{SchemaVersion: reportEvidenceVersion, Evidence: b, Assessment: a})
	if strings.Contains(body, "999") || !strings.Contains(body, "60秒") || !strings.Contains(body, "2个自然日") || strings.Contains(body, "连续3天") {
		t.Fatal(body)
	}
}

func TestEssenceKeepsOpposingSemanticAndExcludesMissing(t *testing.T) {
	b := essenceFixture()
	b.Entries[2].Semantic.Judgement = "contradict"
	b.Entries[2].Semantic.Explanation = "实际域名与情报关联域名不同"
	b.Entries = append(b.Entries, ReportEvidence{ID: "E005", Name: "缺失材料", Status: "missing"}, ReportEvidence{ID: "E006", Name: "未命中", Status: "not_observed"})
	e := buildReportEssence(b)
	opposing := false
	for _, item := range e.Items {
		if item.ID == "E003" && item.Role == "opposing" {
			opposing = true
		}
		if item.ID == "E005" || item.ID == "E006" {
			t.Fatal("gap promoted")
		}
	}
	if !opposing {
		t.Fatal("confirmed opposing interpretation dropped")
	}
}

func TestEssenceDefaultScheduleAndDNSAreQualified(t *testing.T) {
	b := ReportEvidenceBundle{SelectedIDs: []string{"E001", "E002"}, Entries: []ReportEvidence{
		{ID: "E001", Feature: "schedule", Status: "observed", Measurements: map[string]any{"policy_source": "报告默认工作时段规则", "comparison_hours": "08:00—20:00", "saved_hits": 10, "outside_hits": 3, "outside_percent": 30, "active_days": 2, "longest_consecutive_days": 1}},
		{ID: "E002", Feature: "dns_connection", Status: "observed", Measurements: map[string]any{"dns_query": "example.org", "answer_ip": "192.0.2.1", "delay_seconds": 20, "sni": "example.org"}},
	}}
	e := buildReportEssence(b)
	if !strings.Contains(e.Items[0].Summary, "默认") || !strings.Contains(e.Items[1].Summary, "解析后连接") || strings.Contains(e.Items[1].Summary, "攻击源") {
		t.Fatal(e.Items)
	}
}

func TestEssenceOldNarrativeRetainsModelInterpretations(t *testing.T) {
	b := ReportEvidenceBundle{Entries: []ReportEvidence{{ID: "E001", Family: "fact:test"}}}
	a := ReportAssessment{Supporting: []ReportReason{{EvidenceIDs: []string{"E001"}}}, Interpretations: []ReportInterpretation{{EvidenceID: "E001", Meaning: "旧报告的保存解释"}}}
	body := renderReportMarkdown(ReportDocument{SchemaVersion: "evidence-report-1.4", Evidence: b, Assessment: a})
	if !strings.Contains(body, "旧报告的保存解释") {
		t.Fatal("old stored rendering changed")
	}
}

func TestEssenceBindsMaterialSourcesAndRetainsCompositeLinks(t *testing.T) {
	b := essenceFixture()
	sem := b.Entries[2].Semantic
	sem.FactRefs = nil
	sem.MaterialRefs = []string{"actual-material"}
	sem.Judgement = "neutral"
	b.Entries[2].MaterialSourceIDs = map[string][]string{"actual-material": b.Entries[0].SourceIDs}
	e := buildReportEssence(b)
	if len(e.Items) != 2 || len(e.Trace[3].RelatedEvidenceIDs) == 0 {
		t.Fatal("material binding lost", e)
	}
	b.Entries[2].MaterialSourceIDs = map[string][]string{"actual-material": []string{"unrelated"}}
	e = buildReportEssence(b)
	if len(e.Items[0].Interpretations) != 0 {
		t.Fatal("unrelated material attached")
	}
}

func TestEssenceAdaptersCoverEveryDefinitionWithoutClaimingExecution(t *testing.T) {
	b := essenceFixture()
	rows := reportEssenceAdapters(b)
	if len(rows) != len(evidence.Definitions())+len(evidence.SemanticDefinitions()) || len(rows) != 82 {
		t.Fatal("catalog projection incomplete")
	}
	for _, row := range rows {
		if row["rule_id"] == evidence.FactID("F_DGA_LEXICAL") && row["observed_instances"] != 0 {
			t.Fatal("registration reported as execution")
		}
	}
}

func TestEssenceHistoryBindingSeparatesExplicitCurrentSources(t *testing.T) {
	b := essenceFixture()
	b.Entries = b.Entries[:3]
	b.SelectedIDs = []string{"E001", "E003"}
	b.Entries[0].FactID = "F_HIST_ASSET_IOC_RECURRENCE"
	b.Entries[0].Finding.FactID = b.Entries[0].FactID
	b.Entries[0].SourceIDs = []string{"current", "prior-A", "prior-B"}
	b.CurrentSourceIDs = []string{"current"}
	b.Entries[2].Semantic.FactRefs = nil
	b.Entries[2].Semantic.MaterialRefs = []string{"history"}
	b.Entries[2].Semantic.Judgement = "neutral"
	b.Entries[2].MaterialSourceIDs = map[string][]string{"history": []string{"prior-A", "prior-B"}}
	e := buildReportEssence(b)
	if len(e.Items) != 1 || len(e.Items[0].Interpretations) != 1 {
		t.Fatal("history source binding failed", e)
	}
	b.CurrentSourceIDs = nil
	e = buildReportEssence(b)
	if len(e.Items[0].Interpretations) != 0 {
		t.Fatal("guessed current source identities")
	}
}
