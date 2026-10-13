package service

import (
	"fmt"
	"strings"
	"time"
	"vulnscan-backend/traffic/internal/domain"
)

const reportFivePartLayout = "five-part-v1"

func reportEventOverview(event domain.Event, raw, assets string) map[string]string {
	c := decodeEventContext(ModelTimeContext(raw))
	value := func(keys ...string) string {
		for _, key := range keys {
			if v := c[key]; v != nil && fmt.Sprint(v) != "" {
				return fmt.Sprint(v)
			}
		}
		return "未提供"
	}
	return map[string]string{
		"事件ID": event.EventID, "事件名称": firstNonEmpty(event.EventName, event.Title, "未提供"),
		"资产与业务归属": firstNonEmpty(assets, "未提供"),
		"通信源":     value("src_ip", "threat_source"), "通信目标": value("dst_ip", "victim_target"),
		"目标端口": value("dst_port"), "协议": value("protocol"),
		"首次活动（北京时间）": value("first_time", "occurrence_time"), "末次活动（北京时间）": value("last_time", "last_seen_at"),
		"已保存命中记录数": value("occurrence_count", "hit_count"),
	}
}

func renderFivePartReport(doc ReportDocument) string {
	var w strings.Builder
	a, b := doc.Assessment, doc.Evidence
	verdict := map[string]string{"suspicious": "可疑通联", "likely_malicious": "较可能属于恶意活动", "likely_benign": "较可能属于正常业务", "insufficient": "证据不足，性质待核查"}[a.Verdict]
	probability := "暂无法确定"
	if a.Probability != nil {
		probability = fmt.Sprintf("%d%%", *a.Probability)
	}
	fmt.Fprintf(&w, "## 一、研判结论\n\n本次事件判断为%s，属于恶意活动的概率为%s。\n\n%s\n\n", verdict, probability, reportCell(a.ProbabilityReason))
	overview := map[string]string{}
	for k, v := range doc.EventOverview {
		overview[k] = v
	}
	o := b.Overview
	if !o.First.IsZero() {
		zone := time.FixedZone("Asia/Shanghai", 8*3600)
		overview["首次活动（北京时间）"] = o.First.In(zone).Format("2006-01-02 15:04:05")
		overview["末次活动（北京时间）"] = o.Last.In(zone).Format("2006-01-02 15:04:05")
	}
	if len(o.Tuples) > 0 {
		sources, destinations, protocols := []string{}, []string{}, []string{}
		for _, t := range o.Tuples {
			sources = append(sources, t.Source)
			destinations = append(destinations, t.Destination)
			protocols = append(protocols, t.Protocol)
		}
		overview["通信源"] = strings.Join(compactReportRefs(sources), "、")
		overview["通信目标"] = strings.Join(compactReportRefs(destinations), "、")
		overview["协议"] = strings.Join(compactReportRefs(protocols), "、")
	}
	if o.SavedHits > 0 {
		overview["已保存命中记录数"] = fmt.Sprint(o.SavedHits)
	}
	w.WriteString("## 二、事件概览\n\n| 项目 | 内容 |\n| --- | --- |\n")
	for _, key := range []string{"事件ID", "事件名称", "资产与业务归属", "通信源", "通信目标", "目标端口", "协议", "首次活动（北京时间）", "末次活动（北京时间）", "已保存命中记录数"} {
		fmt.Fprintf(&w, "| %s | %s |\n", key, reportCell(firstNonEmpty(overview[key], "未提供")))
	}
	if len(o.Tuples) > 0 {
		w.WriteString("\n| 源地址与端口 | 目的地址与端口 | 协议 | 告警命中次数 |\n| --- | --- | --- | --- |\n")
		for _, tuple := range o.Tuples {
			fmt.Fprintf(&w, "| %s | %s | %s | %d |\n", reportCell(tuple.Source), reportCell(tuple.Destination), reportCell(tuple.Protocol), tuple.Hits)
		}
	}
	w.WriteString("\n## 三、关键证据\n\n")
	meanings := map[string][]string{}
	for _, i := range a.Interpretations {
		meanings[i.EvidenceID] = append(meanings[i.EvidenceID], i.Meaning)
	}
	for _, group := range []struct {
		label   string
		reasons []ReportReason
	}{{"支持依据", a.Supporting}, {"反向依据", a.Opposing}, {"替代解释", a.Alternatives}} {
		for _, r := range group.reasons {
			for _, id := range r.EvidenceIDs {
				text := group.label + "：" + r.Explanation
				if !strings.Contains(strings.Join(meanings[id], "；"), r.Explanation) {
					meanings[id] = append(meanings[id], text)
				}
			}
		}
	}
	ids := b.SelectedIDs
	if b.Essence != nil {
		ids = nil
		for _, item := range b.Essence.Items {
			ids = append(ids, item.ID)
		}
	}
	for number, id := range ids {
		for _, e := range b.Entries {
			if e.ID == id {
				result := e.Result
				if b.Essence != nil {
					for _, item := range b.Essence.Items {
						if item.ID == id {
							result = item.Summary
						}
					}
				}
				fmt.Fprintf(&w, "%d. %s【%s】：%s。%s（来源：%s）\n", number+1, id, reportCell(e.Name), reportCell(result), reportCell(strings.Join(meanings[id], "；")), reportCell(e.Source))
			}
		}
	}
	w.WriteString("\n## 四、风险分析\n\n")
	if len(a.Risks) == 0 {
		w.WriteString("现有材料不足以确认攻击成功或主机失陷，需结合业务归属和应用、主机记录核实风险范围。\n\n")
	}
	for _, r := range a.Risks {
		fmt.Fprintf(&w, "- %s：%s\n", strings.Join(r.EvidenceIDs, "、"), reportCell(r.Impact))
	}
	w.WriteString("\n## 五、处置建议\n\n")
	for i, action := range a.Actions {
		fmt.Fprintf(&w, "%d. %s；目的：%s。依据：%s。\n", i+1, reportCell(action.Action), reportCell(action.Purpose), strings.Join(action.EvidenceIDs, "、"))
	}
	for i, gap := range a.Gaps {
		fmt.Fprintf(&w, "%d. 补充核查：%s。\n", len(a.Actions)+i+1, reportCell(gap))
	}
	if len(a.Actions)+len(a.Gaps) == 0 {
		w.WriteString("暂无具体处置动作，建议补充业务归属与通信记录后复核。\n")
	}
	return w.String()
}
