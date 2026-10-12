package service

import (
	"strings"
	"testing"
	"time"
)

func TestNarrativeOverviewRetainsEveryFiveTupleAndPhysicalDedup(t *testing.T) {
	start := time.Date(2026, 10, 11, 12, 3, 53, 0, time.UTC)
	manifest := SnapshotEvidenceManifest{BoundHits: 3, ReportObservations: []ReportMaterialObservation{
		{Time: start, Source: "172.67.190.89:443", Destination: "180.104.100.118:10564", Protocol: "tcp", PhysicalPacketID: "same"},
		{Time: start, Source: "172.67.190.89:443", Destination: "180.104.100.118:10564", Protocol: "tcp", PhysicalPacketID: "same"},
		{Time: start.Add(time.Minute), Source: "180.104.100.118:10564", Destination: "172.67.190.89:443", Protocol: "tcp", PhysicalPacketID: "response"},
	}}
	o := buildReportEventOverview(EvidenceSnapshot{Count: 3}, manifest)
	if o.SavedHits != 3 || o.PhysicalPackets != 2 || len(o.Tuples) != 2 || o.Last.Sub(o.First) != time.Minute {
		t.Fatal("lost full-membership overview or counted duplicated physical packet", o)
	}
	if o.Tuples[0].Hits+o.Tuples[1].Hits != 3 {
		t.Fatal("overview tuple denominator differs from saved hits")
	}
}

func TestNarrativeReportOrdersBusinessSectionsAndKeepsTechnicalDetailsInAppendix(t *testing.T) {
	_, event, bundle := reportTestBundle(t)
	bundle.Overview = ReportEventOverview{SavedHits: 2, BoundHits: 2, PhysicalPackets: 2, First: time.Date(2026, 10, 11, 12, 3, 53, 0, time.UTC), Last: time.Date(2026, 10, 11, 12, 4, 53, 0, time.UTC), Tuples: []ReportOverviewTuple{{Source: "172.67.190.89:443", Destination: "180.104.100.118:10564", Protocol: "TCP", Hits: 2}}}
	a := validReportAssessment(bundle)
	a.Interpretations[0].Meaning = "与外部目标存在已保存的通信记录"
	doc := ReportDocument{SchemaVersion: reportEvidenceVersion, EventID: event.EventID, Evidence: bundle, Assessment: a}
	text := renderReportMarkdown(doc)
	position := -1
	for _, heading := range []string{"## 一、研判结论", "## 二、事件总览", "## 三、关键证据", "## 四、风险分析", "## 五、建议处置", "## 附录：完整证据与研判依据"} {
		next := strings.Index(text, heading)
		if next <= position {
			t.Fatal("wrong narrative order", heading)
		}
		position = next
	}
	body := text[:strings.Index(text, "## 附录：")]
	for _, forbidden := range []string{"sample_count", "材料缺项", "事实证据与研判意义", "核验概况", "来源索引"} {
		if strings.Contains(body, forbidden) {
			t.Fatal("technical record leaked into narrative", forbidden)
		}
	}
	for _, required := range []string{"2026-10-11 20:03:53", "172.67.190.89:443", "180.104.100.118:10564", "记录频次", "若该通联"} {
		if !strings.Contains(body, required) {
			t.Fatal("business context missing", required)
		}
	}
	if !strings.Contains(text, "## 技术附录") || !strings.Contains(text, "事实证据与研判意义") {
		t.Fatal("detailed evidence discarded instead of moved")
	}
}

func TestNarrativeRiskMustBeBoundConditionalAndCannotAssertCompromise(t *testing.T) {
	_, _, bundle := reportTestBundle(t)
	a := validReportAssessment(bundle)
	if err := validateReportAssessment(a, bundle); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ReportAssessment){
		func(a *ReportAssessment) { a.Risks = nil },
		func(a *ReportAssessment) { a.Risks[0].EvidenceIDs = []string{"E999"} },
		func(a *ReportAssessment) { a.Risks[0].Impact = "资产已经失陷并遭受数据泄露" },
		func(a *ReportAssessment) { a.Risks[0].Impact = "若出现异常，则确认攻击成功" },
	} {
		candidate := validReportAssessment(bundle)
		mutate(&candidate)
		if validateReportAssessment(candidate, bundle) == nil {
			t.Fatal("unbound or asserted impact accepted", candidate.Risks)
		}
	}
}

func TestNarrativeRendererKeepsHistoricalV132Layout(t *testing.T) {
	_, event, b := reportTestBundle(t)
	doc := ReportDocument{SchemaVersion: "evidence-report-1.3.2", EventID: event.EventID, Evidence: b, Assessment: validReportAssessment(b)}
	if renderReportMarkdown(doc) != renderV132ReportMarkdown(doc) || strings.Contains(renderReportMarkdown(doc), "## 一、研判结论") {
		t.Fatal("historical report rewritten")
	}
}
