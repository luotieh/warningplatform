package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type ReportOverviewTuple struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Hits        int    `json:"saved_hits"`
}

type ReportOverviewIOC struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Category   string `json:"category"`
	Source     string `json:"source"`
	Activity   string `json:"activity"`
	Confidence string `json:"confidence"`
}

// Overview is derived from every bound observation and frozen with the report.
// Counts refer to saved hits/packets, never inferred sessions or all traffic.
type ReportEventOverview struct {
	PacketBytes           int                   `json:"packet_bytes,omitempty"`
	SizedPackets          int                   `json:"sized_packets,omitempty"`
	Plaintext             string                `json:"plaintext,omitempty"`
	First                 time.Time             `json:"first"`
	Last                  time.Time             `json:"last"`
	SavedHits             int64                 `json:"saved_hits"`
	BoundHits             int64                 `json:"bound_hits"`
	PhysicalPackets       int                   `json:"physical_packets"`
	UnresolvedPhysicalIDs int                   `json:"unresolved_physical_ids"`
	Tuples                []ReportOverviewTuple `json:"five_tuples"`
	IOCs                  []ReportOverviewIOC   `json:"iocs"`
}

func buildReportEventOverview(snap EvidenceSnapshot, manifest SnapshotEvidenceManifest) ReportEventOverview {
	o := ReportEventOverview{SavedHits: snap.Count, BoundHits: manifest.BoundHits, Tuples: []ReportOverviewTuple{}, IOCs: []ReportOverviewIOC{}}
	tuples := map[string]*ReportOverviewTuple{}
	physical := map[string]bool{}
	sized := map[string]bool{}
	hasPlaintext, allEmpty := false, len(manifest.ReportObservations) > 0
	for _, observation := range manifest.ReportObservations {
		if observation.PhysicalPacketID != "" && !sized[observation.PhysicalPacketID] && observation.PacketBytes != nil {
			sized[observation.PhysicalPacketID] = true
			o.SizedPackets++
			o.PacketBytes += *observation.PacketBytes
		}
		fields := map[string]any{}
		_ = json.Unmarshal(observation.Application, &fields)
		for _, key := range []string{"dns_query", "method", "url", "host", "user_agent", "ssh_banner"} {
			if v, ok := fields[key]; ok && asString(v) != "" {
				hasPlaintext = true
			}
		}
		if observation.PayloadBytes == nil || *observation.PayloadBytes != 0 {
			allEmpty = false
		}
		if o.First.IsZero() || observation.Time.Before(o.First) {
			o.First = observation.Time
		}
		if o.Last.IsZero() || observation.Time.After(o.Last) {
			o.Last = observation.Time
		}
		if observation.PhysicalPacketID == "" {
			o.UnresolvedPhysicalIDs++
		} else {
			physical[observation.PhysicalPacketID] = true
		}
		key := observation.Source + "\x00" + observation.Destination + "\x00" + observation.Protocol
		if tuples[key] == nil {
			tuples[key] = &ReportOverviewTuple{Source: observation.Source, Destination: observation.Destination, Protocol: strings.ToUpper(observation.Protocol)}
		}
		tuples[key].Hits++
	}
	o.PhysicalPackets = len(physical)
	o.Plaintext = "未确认"
	if hasPlaintext {
		o.Plaintext = "有"
	} else if allEmpty {
		o.Plaintext = "无（无应用载荷）"
	}
	keys := []string{}
	for key := range tuples {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		o.Tuples = append(o.Tuples, *tuples[key])
	}
	ioc := nestedMap(snap.Context, "ioc")
	intel := nestedMap(snap.Context, "ioc_evidence")
	if value := asString(ioc["ioc_value"]); value != "" {
		o.IOCs = append(o.IOCs, ReportOverviewIOC{Type: asString(ioc["ioc_type"]), Value: value, Category: asString(ioc["ioc_category"]), Source: firstNonEmpty(asString(intel["source"]), asString(ioc["ioc_source"])), Activity: firstNonEmpty(asString(intel["activity"]), asString(ioc["ioc_description"])), Confidence: asString(intel["confidence"])})
	}
	return o
}

func renderNarrativeReportMarkdown(doc ReportDocument) string {
	var w bytes.Buffer
	a, b := doc.Assessment, doc.Evidence
	verdict := map[string]string{"suspicious": "可疑通联，需要核查并加强防护", "likely_malicious": "证据支持恶意活动研判，应采取针对性防护", "likely_benign": "现有证据支持正常业务解释", "insufficient": "已确认与外部目标存在通联，处置重点为核查通信归属"}[a.Verdict]
	fmt.Fprintf(&w, "## 一、研判结论\n\n%s。%s。\n\n%s\n\n", reportThreatTypeNames[a.ThreatType], verdict, reportCell(a.ProbabilityReason))
	if a.Probability != nil {
		fmt.Fprintf(&w, "本次通信属于恶意活动的研判概率：%d%%。\n\n", *a.Probability)
	}
	fmt.Fprint(&w, "## 二、事件总览\n\n")
	if doc.AssetSection != "" {
		fmt.Fprintf(&w, "涉及资产：\n\n%s\n\n", doc.AssetSection)
	}
	o := b.Overview
	zone := time.FixedZone("Asia/Shanghai", 8*3600)
	if !o.First.IsZero() {
		fmt.Fprintf(&w, "发生时间（北京时间）：%s 至 %s。\n\n", o.First.In(zone).Format("2006-01-02 15:04:05.999999"), o.Last.In(zone).Format("2006-01-02 15:04:05.999999"))
	}
	if o.SavedHits > 0 {
		fmt.Fprintf(&w, "记录频次：观察期间保存%d条告警命中，绑定%d条；已识别%d份去重报文。\n\n", o.SavedHits, o.BoundHits, o.PhysicalPackets)
	}
	if len(o.Tuples) > 0 {
		fmt.Fprint(&w, "| 源地址与端口 | 目的地址与端口 | 协议 | 告警命中次数 |\n| --- | --- | --- | --- |\n")
		for _, tuple := range o.Tuples {
			fmt.Fprintf(&w, "| %s | %s | %s | %d |\n", reportCell(tuple.Source), reportCell(tuple.Destination), reportCell(tuple.Protocol), tuple.Hits)
		}
		fmt.Fprintln(&w)
	}
	for _, ioc := range o.IOCs {
		fmt.Fprintf(&w, "IOC：%s（%s）；情报类别：%s；来源：%s。\n\n", reportCell(ioc.Value), reportCell(ioc.Type), reportCell(ioc.Category), reportCell(ioc.Source))
		if ioc.Activity != "" {
			fmt.Fprintf(&w, "情报关联活动：%s。\n\n", reportCell(ioc.Activity))
		}
		if ioc.Confidence != "" {
			fmt.Fprintf(&w, "情报标注置信度：%s。\n\n", reportCell(ioc.Confidence))
		}
	}
	fmt.Fprint(&w, "## 三、关键证据\n\n")
	if b.Essence != nil {
		for n, item := range b.Essence.Items {
			fmt.Fprintf(&w, "%d. %s：%s。\n\n", n+1, item.ID, strings.TrimRight(reportCell(item.Summary), "。"))
		}
	} else {
		meanings := map[string]string{}
		for _, item := range a.Interpretations {
			meanings[item.EvidenceID] = item.Meaning
		}
		entries := map[string]ReportEvidence{}
		for _, entry := range b.Entries {
			entries[entry.ID] = entry
		}
		seen := map[string]bool{}
		number := 0
		keyReasons := append(append(append([]ReportReason{}, a.Supporting...), a.Opposing...), a.Alternatives...)
		for _, risk := range a.Risks {
			keyReasons = append(keyReasons, ReportReason{EvidenceIDs: risk.EvidenceIDs})
		}
		for _, action := range a.Actions {
			keyReasons = append(keyReasons, ReportReason{EvidenceIDs: action.EvidenceIDs})
		}
		for _, reason := range keyReasons {
			for _, id := range reason.EvidenceIDs {
				entry := entries[id]
				if seen[id] || entry.Family == "snapshot_membership" || strings.HasPrefix(entry.Family, "saved_packet:") {
					continue
				}
				seen[id] = true
				number++
				fmt.Fprintf(&w, "%d. %s：%s。\n\n", number, id, strings.TrimRight(reportCell(meanings[id]), "。"))
			}
		}
	}
	fmt.Fprint(&w, "## 四、风险分析\n\n")
	for _, risk := range a.Risks {
		if b.Essence != nil {
			// The preceding section already states the authoritative facts.
			// Risk prose describes consequences, rather than repeating a model's
			// free-form factual exposure which may enlarge those facts.
			fmt.Fprintf(&w, "%s（依据：%s）。\n\n", strings.TrimRight(reportCell(risk.Impact), "。"), strings.Join(risk.EvidenceIDs, "、"))
		} else {
			fmt.Fprintf(&w, "%s（依据：%s）。%s\n\n", strings.TrimRight(reportCell(risk.Exposure), "。"), strings.Join(risk.EvidenceIDs, "、"), reportCell(risk.Impact))
		}
	}
	fmt.Fprint(&w, "## 五、建议处置\n\n")
	for n, action := range a.Actions {
		fmt.Fprintf(&w, "%d. %s。%s（依据：%s）。\n\n", n+1, strings.TrimRight(reportCell(action.Action), "。"), strings.TrimRight(reportCell(action.Purpose), "。"), strings.Join(action.EvidenceIDs, "、"))
	}
	// Detailed facts, interpretation/probability audit, gaps and provenance remain
	// lossless in appendices. They no longer dictate the narrative body.
	return w.String()
}

func renderReportTechnicalAppendix(doc ReportDocument) string {
	if doc.Evidence.Pipeline != nil && len(doc.Evidence.Normalized.Items) == 0 {
		a := doc.Evidence.Pipeline
		var w strings.Builder
		fmt.Fprintf(&w, "## 附录：完整证据审计索引\n\n快照：%d；命中水位：%d；修订水位：%d。\n\n审计键：%s。完整字段来源、限制及逐实例结果可由报告证据明细接口分页读取。\n\n", a.SnapshotVersion, a.Watermark, a.RevisionWatermark, a.Key)
		for _, check := range a.Checks {
			fmt.Fprintf(&w, "- %s：%s\n", check.ID, check.Status)
		}
		return w.String()
	}
	var w bytes.Buffer
	fmt.Fprint(&w, "## 附录：完整证据与研判依据\n\n")
	legacy := renderV132ReportMarkdown(doc)
	start := strings.Index(legacy, "## 事实证据与研判意义")
	end := strings.Index(legacy, "## 核查及处置建议")
	if start >= 0 && end > start {
		fmt.Fprint(&w, legacy[start:end])
	}
	if appendix := strings.Index(legacy, "## 技术附录"); appendix >= 0 {
		fmt.Fprint(&w, legacy[appendix:])
	}
	return w.String()
}

// Compact overview for the report model. Long IOC activity descriptions are
// already present in the authoritative intelligence evidence, so not repeated.
func reportOverviewPrompt(o ReportEventOverview) map[string]any {
	raw, _ := json.Marshal(o)
	result := map[string]any{}
	_ = json.Unmarshal(raw, &result)
	delete(result, "five_tuples")
	result["five_tuple_location"] = "selected_evidence中saved_activity族的五元组完整分布；不重复输入"
	if items, ok := result["iocs"].([]any); ok {
		for _, ioc := range items {
			delete(ioc.(map[string]any), "activity")
		}
	}
	return result
}
