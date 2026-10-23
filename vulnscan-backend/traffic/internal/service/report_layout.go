package service

import (
	"fmt"
	"strings"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

const reportFivePartLayout = "five-part-v2"
const reportFivePartLegacyLayout = "five-part-v1"

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
		"事件类型": firstNonEmpty(event.EventName, event.Title, event.Category, "未提供"),
		"事件ID": event.EventID, "事件名称": firstNonEmpty(event.EventName, event.Title, "未提供"),
		"资产与业务归属": firstNonEmpty(assets, "未提供"),
		"通信源":     value("src_ip", "threat_source"), "通信目标": value("dst_ip", "victim_target"),
		"源端口": value("src_port"), "目标端口": value("dst_port"), "协议": value("protocol"),
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
	if b.PhaseOne != nil {
		fmt.Fprintf(&w, "## 一、研判结论\n\n本次事件判断为%s，模型估计的恶意活动倾向为%s（未经概率校准）。\n\n%s\n\n", verdict, probability, reportCell(a.ProbabilityReason))
	} else {
		fmt.Fprintf(&w, "## 一、研判结论\n\n本次事件判断为%s，属于恶意活动的概率为%s。\n\n%s\n\n", verdict, probability, reportCell(a.ProbabilityReason))
	}
	if doc.LayoutVersion == reportFivePartLegacyLayout {
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
	} else {
		w.WriteString(renderCompactEventOverview(doc))
	}
	w.WriteString("\n## 三、关键证据\n\n")
	if b.PhaseOne != nil {
		fmt.Fprintf(&w, "一期证据策略分：%d（策略版本：%s；该分数不是已校准概率）。\n\n", b.PhaseOne.Result.Score, reportCell(b.PhaseOne.Result.Policy.Version))
		if b.Pipeline != nil {
			for _, d := range evidence.PhaseOneDefinitions() {
				states := map[string]int{}
				for _, u := range b.PhaseOne.Result.Units {
					if u.ID == d.ID {
						states[u.Status]++
					}
				}
				fmt.Fprintf(&w, "- %s：成立%d；完整未命中%d；材料不足%d；错误%d。\n", d.ID, states["observed"], states["not_observed"], states["missing"], states["execution_error"])
			}
			fmt.Fprintf(&w, "\n逐实例测量值、来源和去重关系见审计键 %s。\n", b.Pipeline.Key)
		} else {
			for _, u := range b.PhaseOne.Result.Units {
				fmt.Fprintf(&w, "- %s：%s；加分%d；原因=%s。\n", u.ID, reportCell(u.Status), u.Score, reportCell(u.Reason))
			}
		}
		w.WriteString("\n")
	}
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

// Keep the old layout immutable so saved report versions remain readable.
func renderCompactEventOverview(doc ReportDocument) string {
	return renderEventOverview(doc, false)
}

func renderEventOverview(doc ReportDocument, complete bool) string {
	var w strings.Builder
	o := doc.Evidence.Overview
	value := func(key string) string { return firstNonEmpty(doc.EventOverview[key], "未提供") }
	window := value("首次活动（北京时间）") + " 至 " + value("末次活动（北京时间）")
	if !o.First.IsZero() {
		zone := time.FixedZone("Asia/Shanghai", 8*3600)
		window = o.First.In(zone).Format("2006-01-02 15:04:05")
		if !o.Last.IsZero() && !o.Last.Equal(o.First) {
			last := o.Last.In(zone)
			if last.Format("2006-01-02") == o.First.In(zone).Format("2006-01-02") {
				window += " 至 " + last.Format("15:04:05")
			} else {
				window += " 至 " + last.Format("2006-01-02 15:04:05")
			}
		}
	}
	tuples := []string{}
	for n, t := range o.Tuples {
		if !complete && n == 3 {
			tuples = append(tuples, fmt.Sprintf("另有%d组五元组", len(o.Tuples)-n))
			break
		}
		row := fmt.Sprintf("%s → %s（%s）", t.Source, t.Destination, t.Protocol)
		if complete {
			row += fmt.Sprintf("：%d条命中", t.Hits)
		}
		tuples = append(tuples, row)
	}
	if len(tuples) == 0 {
		source := value("通信源")
		if port := doc.EventOverview["源端口"]; port != "" && port != "未提供" {
			source += ":" + port
		}
		target := value("通信目标")
		if port := doc.EventOverview["目标端口"]; port != "" && port != "未提供" {
			target += ":" + port
		}
		tuples = append(tuples, source+" → "+target+"（"+value("协议")+"）")
	}
	frequency := "已保存" + value("已保存命中记录数") + "条告警命中"
	if value("已保存命中记录数") == "未提供" {
		frequency = "频次未提供"
	}
	if o.SavedHits > 0 {
		frequency = fmt.Sprintf("观测期间保存%d条告警命中", o.SavedHits)
	}
	intel := []string{}
	for n, i := range o.IOCs {
		if !complete && n == 2 {
			intel = append(intel, fmt.Sprintf("另有%d项IOC", len(o.IOCs)-n))
			break
		}
		fields := []string{i.Value}
		if complete && i.Type != "" {
			fields = append(fields, "类型："+i.Type)
		}
		if complete && i.Activity != "" {
			fields = append(fields, "情报描述："+i.Activity)
		}
		if i.Category != "" {
			fields = append(fields, i.Category)
		}
		if i.Source != "" {
			fields = append(fields, "来源："+i.Source)
		}
		if i.Confidence != "" {
			fields = append(fields, "置信度："+i.Confidence)
		}
		intel = append(intel, strings.Join(fields, "；"))
	}
	if len(intel) == 0 {
		intel = append(intel, "未提供IOC情报")
	}
	w.WriteString("## 二、事件概览\n\n| 项目 | 内容 |\n| --- | --- |\n")
	size := "包数、字节数未确认"
	if o.SizedPackets > 0 {
		size = fmt.Sprintf("%d包、%d字节", o.SizedPackets, o.PacketBytes)
		if o.SizedPackets != o.PhysicalPackets || o.UnresolvedPhysicalIDs > 0 {
			size += "（已核验部分）"
		}
	} else if o.PhysicalPackets > 0 {
		size = fmt.Sprintf("%d包，字节数未确认", o.PhysicalPackets)
	}
	size += "；明文：" + firstNonEmpty(o.Plaintext, "未确认")
	for _, row := range [][2]string{{"事件类型", firstNonEmpty(doc.EventOverview["事件类型"], doc.EventOverview["事件名称"], doc.Title, "未提供")}, {"发生时间（北京时间）", window}, {"通信五元组", strings.Join(tuples, "；")}, {"通信频次", frequency}, {"报文大小", size}, {"IOC情报", strings.Join(intel, "；")}} {
		fmt.Fprintf(&w, "| %s | %s |\n", row[0], reportCell(row[1]))
	}
	return w.String()
}
