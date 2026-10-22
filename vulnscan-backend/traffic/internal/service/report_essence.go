package service

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"vulnscan-backend/evidence"
)

// Only this projection is sent to the report model. The original bundle remains
// immutable and complete, including unsuccessful executions and source IDs.
type ReportEssence struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Summary         string           `json:"result"`
	Role            string           `json:"role"`
	Scope           evidence.Scope   `json:"scope"`
	Window          *evidence.Window `json:"window,omitempty"`
	Details         []string         `json:"detail_ids"`
	Interpretations []string         `json:"interpretations,omitempty"`
}
type ReportEssenceDetail struct {
	ID           string         `json:"id"`
	Measurements map[string]any `json:"measurements,omitempty"`
	Statements   []string       `json:"statements,omitempty"`
}
type ReportEssenceTrace struct {
	RelatedEvidenceIDs []string `json:"related_evidence_ids,omitempty"`
	EntryID            string   `json:"entry_id"`
	EvidenceID         string   `json:"evidence_id,omitempty"`
	DetailID           string   `json:"detail_id,omitempty"`
	Reason             string   `json:"reason"`
	SourceIDs          []string `json:"source_ids,omitempty"`
}
type ReportEssenceBundle struct {
	ProjectionOmitted    int                   `json:"projection_omitted,omitempty"`
	ProjectionByteBudget int                   `json:"projection_byte_budget,omitempty"`
	Version              string                `json:"version"`
	Items                []ReportEssence       `json:"items"`
	Details              []ReportEssenceDetail `json:"details"`
	Trace                []ReportEssenceTrace  `json:"trace"`
}

func buildReportEssence(b ReportEvidenceBundle) ReportEssenceBundle {
	out := ReportEssenceBundle{Version: "report-essence-1.0", Items: []ReportEssence{}, Details: []ReportEssenceDetail{}, Trace: []ReportEssenceTrace{}}
	selected := map[string]bool{}
	for _, id := range b.SelectedIDs {
		selected[id] = true
	}
	entries := append([]ReportEvidence(nil), b.Entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	index := map[string]int{}
	// First retain measured facts and observations. Semantic findings are bound
	// only after all concrete instances have been indexed.
	for _, e := range entries {
		if e.Semantic != nil {
			continue
		}
		reason := ""
		switch {
		case b.PolicyVersion == "evidence-report-1.6" && e.Kind == "observation":
			reason = "overview_only"
		case e.Family == "snapshot_membership":
			reason = "overview_only"
		case strings.HasPrefix(e.Family, "saved_packet:"):
			reason = "raw_bytes_audit_only"
		case e.Status == "missing" || e.Status == "unavailable":
			reason = "missing_material"
		case e.Status == "not_observed":
			reason = "unhit_not_a_proven_negative"
		case !selected[e.ID]:
			reason = "audit_only"
		}
		if reason != "" {
			out.Trace = append(out.Trace, ReportEssenceTrace{EntryID: e.ID, Reason: reason, SourceIDs: e.SourceIDs})
			continue
		}
		d := ReportEssenceDetail{ID: fmt.Sprintf("D%03d", len(out.Details)+1), Measurements: essenceMeasurements(e)}
		if e.Finding != nil {
			for _, limitation := range e.Finding.Limitations {
				d.Statements = append(d.Statements, essenceCleanText(limitation, e.SourceIDs))
			}
		}
		summary := formatEvidenceEssence(e, d.Measurements)
		if summary == "" {
			out.Trace = append(out.Trace, ReportEssenceTrace{EntryID: e.ID, Reason: "no_effective_result", SourceIDs: e.SourceIDs})
			continue
		}
		role := "background"
		if e.Finding != nil && e.Status == "observed" {
			role = "support"
		}
		item := ReportEssence{ID: e.ID, Name: e.Name, Summary: summary, Role: role, Scope: e.Scope, Window: e.Window, Details: []string{d.ID}}
		if len(d.Measurements) == 0 {
			d.Statements = append(d.Statements, summary)
		}
		index[e.ID] = len(out.Items)
		out.Items = append(out.Items, item)
		out.Details = append(out.Details, d)
		out.Trace = append(out.Trace, ReportEssenceTrace{EntryID: e.ID, EvidenceID: e.ID, DetailID: d.ID, Reason: "retained", SourceIDs: e.SourceIDs})
	}
	// Merge empirical interval distribution with a strict periodic finding only
	// when the exact source population, scope and window agree. No IOC-only merge.
	for _, e := range entries {
		if b.PolicyVersion == "evidence-report-1.6" || e.Feature != "time_distribution" {
			continue
		}
		oi, ok := index[e.ID]
		if !ok {
			continue
		}
		for _, f := range entries {
			if f.FactID != evidence.BeaconPeriodic && f.FactID != "F_BEACON_JITTER" {
				continue
			}
			fi, ok := index[f.ID]
			if !ok || !sameEssencePopulation(e, f) {
				continue
			}
			out.Items[fi].Details = append(out.Items[fi].Details, out.Items[oi].Details...)
			out.Items[oi].ID = ""
			index[e.ID] = fi
			for t := range out.Trace {
				if out.Trace[t].EntryID == e.ID {
					out.Trace[t].EvidenceID = f.ID
					out.Trace[t].Reason = "merged_same_interval_population"
				}
			}
			break
		}
	}
	for _, e := range entries {
		if e.Semantic == nil {
			continue
		}
		s := e.Semantic
		tr := ReportEssenceTrace{EntryID: e.ID, SourceIDs: e.SourceIDs}
		if s.DuplicateOf != "" {
			tr.Reason = "duplicate_semantic"
			out.Trace = append(out.Trace, tr)
			continue
		}
		if strings.TrimSpace(s.Explanation) == "" {
			tr.Reason = "no_effective_explanation"
			out.Trace = append(out.Trace, tr)
			continue
		}
		bindings := []int{}
		for _, f := range entries {
			if f.Scope != e.Scope || !essenceWindowsCompatible(f.Window, e.Window) || (f.Finding != nil && f.Finding.SnapshotVersion != s.SnapshotVersion) {
				continue
			}
			match := false
			for _, ref := range s.FactRefs {
				if ref == string(f.FactID) || ref == f.ID || (f.Unified != nil && ref == f.Unified.ID) {
					match = true
				}
			}
			for _, ref := range s.MaterialRefs {
				if sources := e.MaterialSourceIDs[ref]; len(sources) > 0 {
					bound := e
					bound.SourceIDs = sources
					if sameEssencePopulation(bound, f) {
						match = true
					}
					// History findings carry both the current timeline and the
					// referenced history. Compare the latter by removing only
					// explicitly snapshot-bound current identities, never prefixes.
					if strings.HasPrefix(string(f.FactID), "F_HIST_") && len(b.CurrentSourceIDs) > 0 {
						current := map[string]bool{}
						for _, id := range b.CurrentSourceIDs {
							current[id] = true
						}
						historical := f
						historical.SourceIDs = nil
						for _, id := range f.SourceIDs {
							if !current[id] {
								historical.SourceIDs = append(historical.SourceIDs, id)
							}
						}
						if sameEssencePopulation(bound, historical) {
							match = true
						}
					}
				}
			}
			if match {
				if n, ok := index[f.ID]; ok {
					bindings = append(bindings, n)
				}
			}
		}
		bindings = uniqueEssenceIndexes(bindings)
		interpretation := essenceCleanText(s.Explanation, e.SourceIDs)
		if b.PolicyVersion != "evidence-report-1.6" && len(bindings) >= 1 && s.Judgement != "contradict" && (len(bindings) == 1 || s.ExplanationOnly || s.Judgement == "neutral") {
			n := bindings[0]
			ids := []string{}
			for _, bound := range bindings {
				ids = append(ids, out.Items[bound].ID)
			}
			if len(ids) > 1 {
				interpretation = "联合说明（" + strings.Join(ids, "、") + "）：" + interpretation
			}
			detail := ReportEssenceDetail{ID: fmt.Sprintf("D%03d", len(out.Details)+1), Statements: []string{interpretation}}
			for _, q := range s.Quotes {
				detail.Statements = append(detail.Statements, essenceCleanText(q.Excerpt, e.SourceIDs))
			}
			detail.Statements = append(detail.Statements, s.Alternatives...)
			out.Details = append(out.Details, detail)
			for _, bound := range bindings {
				out.Items[bound].Interpretations = append(out.Items[bound].Interpretations, interpretation)
				out.Items[bound].Details = append(out.Items[bound].Details, detail.ID)
			}
			tr.EvidenceID = out.Items[n].ID
			tr.RelatedEvidenceIDs = ids
			tr.DetailID = detail.ID
			tr.Reason = "bound_semantic_explanation"
		} else if selected[e.ID] || ((s.Slot.ID == "R06" || s.Slot.ID == "R07") && len(s.MaterialRefs) > 0) {
			role := "background"
			if !s.ExplanationOnly && s.Judgement == "support" {
				role = "support"
			}
			if s.Judgement == "contradict" {
				role = "opposing"
			}
			detail := ReportEssenceDetail{ID: fmt.Sprintf("D%03d", len(out.Details)+1), Statements: []string{interpretation}}
			for _, q := range s.Quotes {
				detail.Statements = append(detail.Statements, essenceCleanText(q.Excerpt, e.SourceIDs))
			}
			detail.Statements = append(detail.Statements, s.Alternatives...)
			out.Details = append(out.Details, detail)
			out.Items = append(out.Items, ReportEssence{ID: e.ID, Name: e.Name, Summary: interpretation, Role: role, Scope: e.Scope, Window: e.Window, Details: []string{detail.ID}})
			tr.EvidenceID = e.ID
			tr.DetailID = detail.ID
			tr.Reason = "retained_semantic_context"
		} else {
			tr.Reason = "neutral_or_unbound_audit_only"
		}
		out.Trace = append(out.Trace, tr)
	}
	kept := []ReportEssence{}
	for _, item := range out.Items {
		if item.ID != "" {
			kept = append(kept, item)
		}
	}
	out.Items = kept
	sort.SliceStable(out.Items, func(i, j int) bool { return out.Items[i].ID < out.Items[j].ID })
	return out
}

func uniqueEssenceIndexes(v []int) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, n := range v {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}
func essenceWindowsCompatible(a, b *evidence.Window) bool {
	return a != nil && b != nil && !a.Start.IsZero() && a.Start.Equal(b.Start) && a.End.Equal(b.End)
}
func sameEssencePopulation(a, b ReportEvidence) bool {
	if a.Scope != b.Scope || !essenceWindowsCompatible(a.Window, b.Window) || len(a.SourceIDs) == 0 || len(a.SourceIDs) != len(b.SourceIDs) {
		return false
	}
	x, y := append([]string(nil), a.SourceIDs...), append([]string(nil), b.SourceIDs...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}
func essenceCleanText(s string, refs []string) string {
	for _, ref := range refs {
		if ref != "" {
			s = strings.ReplaceAll(s, ref, "来源记录")
		}
	}
	return strings.TrimSpace(s)
}
func essenceMeasurements(e ReportEvidence) map[string]any {
	var value any = e.Measurements
	if e.Finding != nil {
		value = e.Finding.Measurements
	}
	raw, _ := json.Marshal(value)
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	// Retain concentration and intervals, replacing an unbounded time series with
	// its exact peak and peak timestamps. The complete bins remain in the trace bundle.
	if bins, ok := m["五分钟桶次数"].(map[string]any); ok {
		peak := float64(0)
		times := []string{}
		for _, v := range bins {
			if n, ok := v.(float64); ok && n > peak {
				peak = n
			}
		}
		for k, v := range bins {
			if v == peak {
				times = append(times, k)
			}
		}
		sort.Strings(times)
		delete(m, "五分钟桶次数")
		m["最高五分钟桶时间"] = times
		m["最高五分钟命中数"] = peak
		m["非空五分钟桶数"] = len(bins)
	}
	return m
}
func formatEvidenceEssence(e ReportEvidence, m map[string]any) string {
	if e.Finding != nil {
		f := e.Finding
		v := f.Measurements
		switch f.FactID {
		case evidence.BeaconPeriodic, "F_BEACON_JITTER":
			text := "存在周期性通信"
			if f.FactID == "F_BEACON_JITTER" {
				text = "存在带抖动的周期性通信"
			}
			if v.MedianIntervalSeconds != nil {
				text += fmt.Sprintf("，间隔中位数%.6g秒", *v.MedianIntervalSeconds)
			}
			if v.IntervalCV != nil {
				text += fmt.Sprintf("，间隔变异系数%.6g", *v.IntervalCV)
			}
			return text + fmt.Sprintf("；核验样本%d个", v.SampleCount)
		case evidence.MultiDayPersist:
			if v.DaysActive != nil {
				return fmt.Sprintf("已保存记录在%d个自然日出现通信；核验样本%d个", *v.DaysActive, v.SampleCount)
			}
		case "F_HIST_ASSET_IOC_RECURRENCE":
			if _, known := v.Values["dns_records"]; known {
				return fmt.Sprintf("同资产同IOC在已检索历史中出现%.0f条事件，其中传输接触%.0f条、DNS记录%.0f条；混合记录活跃%.0f个自然日，传输日期另见直接通联证据", v.Values["independent_events"], v.Values["transport_contact_records"], v.Values["dns_records"], v.Values["days_active"])
			}
		}
		// Generic adapter is intentionally lossless: every supported rule retains
		// its observed measurements, including unfamiliar metric names and labels.
		return e.Name + "：" + strings.TrimPrefix(reportFactMeasurements(*f), "程序核验：成立；")
	}
	if e.Feature == "schedule" {
		return fmt.Sprintf("按%s比较时段%s，已保存%v条命中中有%v条位于时段之外（%v%%）；实际活跃%v个自然日，最长连续%v天", m["policy_source"], m["comparison_hours"], m["saved_hits"], m["outside_hits"], m["outside_percent"], m["active_days"], m["longest_consecutive_days"])
	}
	if e.Feature == "history_association_transport" {
		dates, _ := m["事件首记录日期次数"].(map[string]any)
		days := []string{}
		for d := range dates {
			days = append(days, d)
		}
		sort.Strings(days)
		span := ""
		if len(days) > 0 {
			span = days[0] + "至" + days[len(days)-1] + "，"
		}
		return fmt.Sprintf("已检索记录中，同资产与IOC %v在%s%d个自然日存在%v条历史传输接触事件；不包含DNS查询", m["IOC"], span, len(days), m["实际传输接触事件数"])
	}
	if e.Feature == "time_distribution" {
		text := fmt.Sprintf("已保存%v条命中，最高五分钟桶包含%v条，占比%.1f%%", m["used_records"], m["最高五分钟命中数"], essenceNumber(m["最高桶占保存命中比例"])*100)
		if v, ok := m["平均间隔秒"]; ok {
			text += fmt.Sprintf("；平均间隔%.6g秒，间隔变异系数%.6g，间隔样本%v个", essenceNumber(v), essenceNumber(m["间隔变异系数"]), m["间隔样本数"])
		}
		return text
	}
	if e.Feature == "history_association" {
		return fmt.Sprintf("已检索同资产历史事件%v条，其中DNS记录%v条、传输接触%v条；与当前IOC %v相同的记录%v条。不同IOC仅作资产活动背景", m["used_records"], m["DNS记录"], m["传输接触记录"], m["历史IOC主体"], m["相同IOC记录数"])
	}
	if e.Feature == "saved_activity" {
		text := fmt.Sprintf("固定快照保存%v条命中，涉及%v个远端端点", m["saved_hits"], m["remote_endpoint_count"])
		if essenceNumber(m["payload_samples"]) > 0 {
			text += fmt.Sprintf("；已核验%v份报文的应用载荷，共%v字节，仅代表这些报文", m["payload_samples"], m["payload_total_bytes"])
		}
		return text
	}
	if e.Feature == "dns_connection" {
		return fmt.Sprintf("同资产的DNS查询%v应答包含%v，%v秒后出现对该IP的连接且SNI为%v；关联为解析后连接", m["dns_query"], m["answer_ip"], m["delay_seconds"], m["sni"])
	}
	if e.Feature == "application_fields" {
		parts := []string{}
		for _, k := range []string{"tls_sni", "sni", "dns_query", "http_host", "http_method", "http_url"} {
			if v, ok := m[k]; ok {
				parts = append(parts, k+"为"+essenceMetricText(v))
			}
		}
		if len(parts) > 0 {
			return "实际应用字段：" + strings.Join(parts, "；")
		}
	}
	if e.Feature == "ioc_background" {
		category := fmt.Sprint(m["category"])
		if category == "phishing" {
			category = "钓鱼活动关联"
		}
		return fmt.Sprintf("目标%v被%v情报标注为%s；情报活动详情见数据依据", m["value"], m["source"], category)
	}
	if e.Feature == "network_fields" {
		text := "远端端口记录：" + essenceMetricText(m["远端端点端口次数"])
		if v, ok := m["已有TCP状态次数"].(map[string]any); ok && len(v) > 0 {
			text += "；TCP状态：" + essenceMetricText(v)
		}
		if v, ok := m["偏离常见或专用端口"].(map[string]any); ok && len(v) > 0 {
			text += "；偏离常见或专用端口：" + essenceMetricText(v)
		}
		return text
	}
	// Other practical features have their full metrics in D details. Keep the
	// concrete distribution in the sentence; omit counters for adapter execution.
	if len(m) > 0 {
		parts := []string{}
		keys := []string{}
		for k := range m {
			if k != "used_records" && k != "excluded_records" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, k+"："+essenceMetricText(m[k]))
		}
		return e.Name + "；" + strings.Join(parts, "；")
	}
	return essenceCleanText(e.Result, e.SourceIDs)
}

func essenceNumber(v any) float64 { n, _ := v.(float64); return n }
func essenceMetricText(v any) string {
	if m, ok := v.(map[string]any); ok {
		keys := []string{}
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := []string{}
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
		}
		return strings.Join(parts, "、")
	}
	raw, _ := json.Marshal(v)
	return strings.Trim(string(raw), "\"")
}

func reportEssenceFor(b ReportEvidenceBundle) ReportEssenceBundle {
	if b.Essence != nil {
		return *b.Essence
	}
	return buildReportEssence(b)
}

func reportApplicationMeasurements(rows []string) map[string]any {
	out := map[string]any{}
	values := map[string][]any{}
	for _, row := range rows {
		var fields map[string]any
		if json.Unmarshal([]byte(row), &fields) != nil {
			continue
		}
		for k, v := range fields {
			values[k] = append(values[k], v)
		}
	}
	for k, v := range values {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = v
		}
	}
	return out
}
func reportIOCMeasurements(context map[string]any) map[string]any {
	ioc := nestedMap(context, "ioc")
	intel := nestedMap(context, "ioc_evidence")
	return map[string]any{"value": ioc["ioc_value"], "type": ioc["ioc_type"], "category": ioc["ioc_category"], "description": ioc["ioc_description"], "source": firstNonEmpty(asString(intel["source"]), asString(ioc["ioc_source"])), "activity": firstNonEmpty(asString(intel["activity"]), asString(ioc["ioc_description"])), "confidence": intel["confidence"], "threat_labels": intel["threat_labels"]}
}

// Covers every catalog definition, including those without any executed or
// observed instance in this report. Registration is never reported as a hit.
func reportEssenceAdapters(b ReportEvidenceBundle) []map[string]any {
	out := []map[string]any{}
	essence := reportEssenceFor(b)
	mappings := map[string]string{}
	for _, t := range essence.Trace {
		mappings[t.EntryID] = t.EvidenceID
	}
	for _, d := range evidence.Definitions() {
		mode := "generic_measurements"
		if d.ID == evidence.BeaconPeriodic || d.ID == "F_BEACON_JITTER" || d.ID == evidence.MultiDayPersist {
			mode = "typed_summary"
		}
		instances, hits, projected := 0, 0, []string{}
		for _, f := range b.FactChecks {
			if f.FactID == d.ID {
				instances++
				if f.Status == evidence.Observed {
					hits++
				}
			}
		}
		for _, e := range b.Entries {
			if e.FactID == d.ID && mappings[e.ID] != "" {
				projected = append(projected, mappings[e.ID])
			}
		}
		out = append(out, map[string]any{"kind": "fact", "rule_id": d.ID, "adapter": mode, "computed_instances": instances, "observed_instances": hits, "essence_ids": projected})
	}
	for _, d := range evidence.SemanticDefinitions() {
		executed, accepted := 0, 0
		projected := []string{}
		for _, x := range b.SemanticChecks {
			if x.Slot == d.Key && x.Status == "accepted" {
				executed++
			}
		}
		for _, e := range b.Entries {
			if e.Semantic != nil && e.Semantic.Slot == d.Key {
				accepted++
				if mappings[e.ID] != "" {
					projected = append(projected, mappings[e.ID])
				}
			}
		}
		out = append(out, map[string]any{"kind": "semantic", "slot": d.Key, "adapter": "reference_bound_interpretation", "accepted_executions": executed, "accepted_instances": accepted, "essence_ids": projected})
	}
	return out
}

func essenceWeightPolicy(b ReportEvidenceBundle) map[string]any {
	if b.Scoring != nil {
		return reportScoreModelProjection(b.Scoring)
	}
	// Reuse the existing coefficients, remap their references and take only the
	// strongest instruction per resulting evidence and dependency group.
	original := b
	b.Essence = nil
	policy := reportWeightPolicy(b)
	essence := reportEssenceFor(original)
	mapping := map[string]string{}
	for _, t := range essence.Trace {
		if t.EvidenceID != "" {
			mapping[t.EntryID] = t.EvidenceID
		}
	}
	rows := []map[string]any{}
	seen := map[string]int{}
	for _, row := range policy["enhanced_temporal"].([]map[string]any) {
		id := mapping[fmt.Sprint(row["evidence_id"])]
		if id == "" {
			continue
		}
		row["evidence_id"] = id
		key := id + ":" + fmt.Sprint(row["dependency_group"])
		if n, ok := seen[key]; ok {
			if row["relative_influence"].(float64) > rows[n]["relative_influence"].(float64) {
				rows[n] = row
			}
		} else {
			seen[key] = len(rows)
			rows = append(rows, row)
		}
	}
	policy["enhanced_temporal"] = rows
	policy["version"] = "report-weights-1.5"
	return policy
}
