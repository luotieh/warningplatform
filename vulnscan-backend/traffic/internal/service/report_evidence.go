package service

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

const reportEvidenceVersion = "evidence-report-1.0"

// ReportEvidence is built from complete engine outputs BEFORE model projection.
// Source identities stay in the immutable journal, not in the model's prose.
type ReportEvidence struct {
	ID             string                    `json:"id"`
	Kind           string                    `json:"kind"`
	Name           string                    `json:"name"`
	Status         string                    `json:"status"`
	Result         string                    `json:"result"`
	Source         string                    `json:"source"`
	Scope          evidence.Scope            `json:"scope"`
	Window         *evidence.Window          `json:"window,omitempty"`
	FactID         evidence.FactID           `json:"fact_id,omitempty"`
	SourceIDs      []string                  `json:"source_ids,omitempty"`
	Dependencies   []evidence.Dependency     `json:"dependencies,omitempty"`
	Finding        *evidence.Finding         `json:"finding,omitempty"`
	Semantic       *evidence.SemanticFinding `json:"semantic,omitempty"`
	Family         string                    `json:"family"`
	RelatedFactIDs []string                  `json:"related_fact_ids,omitempty"`
}

type ReportEvidenceBundle struct {
	SnapshotVersion   int64                        `json:"snapshot_version"`
	Watermark         int64                        `json:"watermark"`
	RevisionWatermark int64                        `json:"revision_watermark"`
	SourceEvents      []string                     `json:"source_events"`
	FactStatus        string                       `json:"fact_status"`
	FactCounts        map[string]int               `json:"fact_counts"`
	SemanticCounts    map[string]int               `json:"semantic_counts"`
	Entries           []ReportEvidence             `json:"entries"`
	SelectedIDs       []string                     `json:"selected_ids"`
	SelectionOmitted  int                          `json:"selection_omitted"`
	FactChecks        []evidence.Finding           `json:"fact_checks"`
	SemanticChecks    []evidence.SemanticExecution `json:"semantic_checks"`
	FactCoverage      []SnapshotFactCoverage       `json:"fact_coverage"`
}

func buildReportEvidence(event domain.Event, snap EvidenceSnapshot, f SnapshotFactEvaluation, sem ReportSemanticEvaluation) ReportEvidenceBundle {
	b := ReportEvidenceBundle{SnapshotVersion: snap.Version, FactStatus: f.Status, FactCounts: map[string]int{}, SemanticCounts: map[string]int{}, Entries: []ReportEvidence{}, SelectedIDs: []string{}, FactChecks: []evidence.Finding{}, SemanticChecks: []evidence.SemanticExecution{}}
	b.FactCoverage = append([]SnapshotFactCoverage(nil), f.Manifest.FactCoverage...)
	b.Watermark, b.RevisionWatermark, b.SourceEvents = snap.Watermark, snap.RevisionWatermark, append([]string(nil), snap.Sources...)
	add := func(e ReportEvidence) {
		e.ID = fmt.Sprintf("E%03d", len(b.Entries)+1)
		b.Entries = append(b.Entries, e)
	}
	if snap.Version > 0 && f.Manifest.LoadedHits == snap.Count && snap.Count > 0 {
		add(ReportEvidence{Kind: "observation", Name: "已保存告警命中", Status: "observed", Result: fmt.Sprintf("固定快照保存%d条告警命中；已加载%d条，已绑定%d条", snap.Count, f.Manifest.LoadedHits, f.Manifest.BoundHits), Source: "固定版本事件快照", Family: "snapshot_membership"})
	}
	// Intel is attributed background, never upgraded to an independently verified
	// malicious classification. Preserve its actual supplied fields and source.
	for _, key := range []string{"ioc", "ioc_evidence"} {
		if v, ok := snap.Context[key]; ok && v != nil {
			raw, _ := json.Marshal(boundedEvidenceValue(v, 0))
			if string(raw) != "{}" && string(raw) != "null" {
				add(ReportEvidence{Kind: "intelligence", Name: "已保存威胁情报背景", Status: "context", Result: semanticSummaryText(string(raw), 900), Source: "事件保存的情报字段（来源及置信度见记录）", Family: "ioc_intelligence"})
			}
		}
	}
	// Actual saved bytes are observations, not automatically a TLS version,
	// command, malicious payload or verified session volume.
	for n, sample := range snap.Evidence {
		if n >= 2 {
			break
		}
		payload := asString(sample["payload_hex"])
		if raw, err := hex.DecodeString(payload); err == nil && len(raw) > 0 {
			prefix := raw[:min(48, len(raw))]
			add(ReportEvidence{Kind: "observation", Name: "已保存报文片段", Status: "observed", Result: fmt.Sprintf("保存片段前%d字节（hex）：%s；通信元数据：%s → %s；协议字段=%s", len(prefix), hex.EncodeToString(prefix), asString(sample["src_ip"]), asString(sample["dst_ip"]), asString(sample["protocol"])), Source: "当前快照代表报文（原始记录保留）", SourceIDs: []string{asString(sample["hit_id"])}, Family: "saved_packet:" + asString(sample["hit_id"])})
		}
	}
	names := map[evidence.FactID]string{}
	for _, d := range evidence.Definitions() {
		names[d.ID] = d.Description
	}
	if f.Result != nil {
		b.FactChecks = append(b.FactChecks, f.Result.Findings...)
		// Stable identities independent of map traversal and display priority.
		sort.Slice(b.FactChecks, func(i, j int) bool {
			a, z := b.FactChecks[i], b.FactChecks[j]
			return string(a.FactID)+scopeKey(a.Scope) < string(z.FactID)+scopeKey(z.Scope)
		})
		for _, finding := range b.FactChecks {
			b.FactCounts[string(finding.Status)]++
			if finding.Status == evidence.Missing {
				continue
			}
			copy := finding
			add(ReportEvidence{Kind: "fact", Name: names[finding.FactID], Status: string(finding.Status), Result: reportFactMeasurements(finding), Source: "确定性事实规则 / " + finding.RuleVersion, Scope: finding.Scope, Window: finding.Window, FactID: finding.FactID, SourceIDs: append([]string(nil), finding.SourceIDs...), Dependencies: finding.Dependencies, Finding: &copy, Family: "fact:" + string(finding.FactID)})
		}
	}
	if sem.Result != nil {
		b.SemanticChecks = append(b.SemanticChecks, sem.Result.Plan.Executions...)
		for _, x := range b.SemanticChecks {
			b.SemanticCounts[x.Status]++
		}
		for _, finding := range sem.Result.Findings {
			if finding.DuplicateOf != "" {
				continue
			}
			copy := finding
			window := evidence.Window{Start: finding.Window.Start, End: finding.Window.End, Convention: "analysis_half_open"}
			ids := []string{}
			seenIDs := map[string]bool{}
			dependencies := []evidence.Dependency{}
			for _, task := range sem.Result.Plan.Tasks {
				if task.ID == finding.TaskID {
					for _, m := range task.Materials {
						dependencies = append(dependencies, evidence.Dependency{Kind: m.Kind, Version: m.SourceVersion, SourceIDs: m.SourceIDs})
						for _, id := range m.SourceIDs {
							if !seenIDs[id] {
								ids = append(ids, id)
								seenIDs[id] = true
							}
						}
					}
				}
			}
			add(ReportEvidence{Kind: "semantic", Name: reportSemanticName(finding.Slot), Status: finding.Judgement, Result: semanticSummaryText(finding.Explanation, 350), Source: "通过引用与强度校验的模型解释", Scope: finding.Scope, Window: &window, Semantic: &copy, SourceIDs: ids, Dependencies: dependencies, Family: "semantic:" + finding.PropositionID, RelatedFactIDs: finding.NonAdditiveWith})
		}
	}
	// Observed facts first. Negative facts only when relevant to protocol/type;
	// missing rules are in the appendix, never promoted to negative evidence.
	candidates := append([]ReportEvidence(nil), b.Entries...)
	score := func(e ReportEvidence) int {
		if e.Kind == "fact" && e.Status == "observed" {
			return 0
		}
		if e.Kind == "observation" {
			return 1
		}
		if e.Kind == "intelligence" {
			return 2
		}
		if e.Kind == "semantic" {
			return 3
		}
		return 4
	}
	sort.SliceStable(candidates, func(i, j int) bool { return score(candidates[i]) < score(candidates[j]) })
	budget := 0
	for _, e := range candidates {
		if e.Status == "not_observed" && !reportFactRelevant(e.FactID, event, snap) {
			continue
		}
		raw, _ := json.Marshal(reportEvidencePromptEntry(e))
		if len(b.SelectedIDs) >= 12 || budget+utf8.RuneCount(raw) > 6000 {
			continue
		}
		b.SelectedIDs = append(b.SelectedIDs, e.ID)
		budget += utf8.RuneCount(raw)
	}
	b.SelectionOmitted = len(b.Entries) - len(b.SelectedIDs)
	return b
}

func reportSemanticName(slot evidence.SlotKey) string {
	names := map[string]string{"S01": "指令意图解释", "S02": "双向指令交互解释", "S03": "UA与行为一致性", "S04": "DNS编码内容解释", "S05": "页面欺骗语义", "S06": "凭据提交意图", "S07": "敏感上传语义", "S08": "分块传输语义", "S09": "请求载荷意图", "S10": "协议应答含义", "S11": "挖矿交互语义", "S12": "域名与品牌语义", "S13": "解码载荷意图", "S14": "正常业务替代解释", "S15": "阶段与信息缺口", "BT-S01": "群体协同行为解释", "SC01": "角色与作息一致性", "SC02": "群体替代解释", "SC03": "品牌与字段一致性", "R06": "历史事件参考", "R07": "历史误报参考"}
	if name := names[slot.ID]; name != "" {
		return "语义解释：" + name
	}
	return "语义解释：" + slot.Target
}

func reportFactRelevant(id evidence.FactID, event domain.Event, snap EvidenceSnapshot) bool {
	context := strings.ToLower(event.EventName + " " + event.Category + " " + event.Message)
	for _, e := range snap.Evidence {
		if app, ok := e["app"].(map[string]any); ok {
			raw, _ := json.Marshal(app)
			context += " " + strings.ToLower(string(raw))
		}
	}
	switch {
	case strings.HasPrefix(string(id), "F_DNS"), strings.HasPrefix(string(id), "F_DGA"), strings.Contains(string(id), "NXDOMAIN"):
		return strings.Contains(context, "dns")
	case strings.HasPrefix(string(id), "F_HTTP"), strings.HasPrefix(string(id), "F_URL"), strings.HasPrefix(string(id), "F_CRED"), strings.HasPrefix(string(id), "F_FORM"), strings.Contains(string(id), "BRAND"), strings.Contains(string(id), "REDIRECT"):
		return strings.Contains(context, "http") || strings.Contains(context, "phishing")
	case strings.HasPrefix(string(id), "F_TLS"):
		return strings.Contains(context, "tls")
	default:
		return true
	}
}

func reportFactMeasurements(f evidence.Finding) string {
	parts := []string{fmt.Sprintf("核验样本数=%d", f.Measurements.SampleCount)}
	if f.Status == evidence.Observed {
		parts = append([]string{"程序核验：成立"}, parts...)
	}
	if v := f.Measurements.MedianIntervalSeconds; v != nil {
		parts = append(parts, fmt.Sprintf("间隔中位数=%.6g秒", *v))
	}
	if v := f.Measurements.IntervalCV; v != nil {
		parts = append(parts, fmt.Sprintf("间隔变异系数=%.6g", *v))
	}
	if v := f.Measurements.DaysActive; v != nil {
		parts = append(parts, fmt.Sprintf("活跃天数=%d", *v))
	}
	if v := f.Measurements.MaxPackets; v != nil {
		parts = append(parts, fmt.Sprintf("最大包数=%d", *v))
	}
	keys := []string{}
	for k := range f.Measurements.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	metricNames := map[string]string{"credential_post_count": "凭据字段POST请求数", "repeat_count": "重复次数", "entropy": "熵", "unique_domain_count": "不同域名数", "sample_count": "样本数", "duration_seconds": "持续秒数", "total_bytes": "核验字节数", "cv": "变异系数", "p_value": "检验p值"}
	for _, k := range keys {
		name := metricNames[k]
		if name == "" {
			name = k
		}
		parts = append(parts, fmt.Sprintf("%s=%.6g", name, f.Measurements.Values[k]))
	}
	for _, label := range f.Measurements.Labels {
		parts = append(parts, label)
	}
	if f.Status == evidence.NotObserved {
		parts = append(parts, "在当前核验范围内未满足该规则条件")
	}
	return strings.Join(parts, "；")
}

func reportEvidencePromptEntry(e ReportEvidence) map[string]any {
	out := map[string]any{"id": e.ID, "kind": e.Kind, "name": e.Name, "status": e.Status, "result": e.Result, "source": e.Source, "scope": e.Scope, "window": e.Window, "family": e.Family, "related_fact_ids": e.RelatedFactIDs}
	if e.Finding != nil {
		out["fact_id"] = e.FactID
		out["measurements"] = e.Finding.Measurements
		out["parameters"] = e.Finding.Parameters
		out["quality"] = e.Finding.Quality
		out["eligibility"] = e.Finding.Eligibility
	}
	if e.Semantic != nil {
		out["judgement"] = e.Semantic.Judgement
		out["strength"] = e.Semantic.Strength
		out["explanation_only"] = e.Semantic.ExplanationOnly
	}
	return out
}

type ReportDocument struct {
	SchemaVersion   string               `json:"schema_version"`
	SummaryID       int64                `json:"summary_id"`
	EventID         string               `json:"event_id"`
	Title           string               `json:"title"`
	AnalysisVersion int                  `json:"analysis_version"`
	Kind            string               `json:"kind"`
	CreatedAt       time.Time            `json:"created_at"`
	Evidence        ReportEvidenceBundle `json:"evidence"`
	Assessment      ReportAssessment     `json:"assessment"`
	Markdown        string               `json:"markdown"`
	Validation      string               `json:"validation"`
	ModelIdentity   string               `json:"model_identity"`
	AssetSection    string               `json:"asset_registry"`
}

func reportDocumentKey(eventID string, summaryID int64) string {
	return fmt.Sprintf("%s:%d", eventID, summaryID)
}
