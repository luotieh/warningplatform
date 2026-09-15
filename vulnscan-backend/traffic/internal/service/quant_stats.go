package service

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

// quantStatsKey 是 event context 中量化统计的 JSON 键。
const quantStatsKey = "quant_stats"

// peakWindowSec 突发窗口宽度（与报告示例的"5 分钟"对齐）。
const peakWindowSec = 5 * 60

// initQuantStats 在事件首次创建时初始化量化统计（occurrence_count=1）。
func initQuantStats(ctx map[string]any, ly map[string]any) {
	qs := newQuantStats()
	occ := firstNonEmpty(asString(ly["occurrence_time"]), asString(ly["time"]))
	qs.WindowStart = occ
	qs.WindowEnd = occ
	qs.OccurrenceCount = 1
	applyHitStats(qs, ly)
	qs.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	ctx[quantStatsKey] = toMap(qs)
}

// updateQuantStats 在 mergeOccurrence 合并命中时增量累计量化统计。
func updateQuantStats(ctx map[string]any, ly map[string]any) {
	raw, _ := ctx[quantStatsKey].(map[string]any)
	if raw == nil {
		raw = toMap(newQuantStats())
	}
	qs := fromMap(raw)
	if qs == nil {
		qs = newQuantStats()
	}
	occ := firstNonEmpty(asString(ly["occurrence_time"]), asString(ly["time"]))
	qs.OccurrenceCount++
	if occ != "" {
		if qs.WindowStart == "" || parseOccurrenceTime(occ).Before(parseOccurrenceTime(qs.WindowStart)) {
			qs.WindowStart = occ
		}
		if parseOccurrenceTime(occ).After(parseOccurrenceTime(qs.WindowEnd)) {
			qs.WindowEnd = occ
		}
	}
	applyHitStats(qs, ly)
	qs.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	ctx[quantStatsKey] = toMap(qs)
}

// freezeQuantStats 在事件收敛时冻结量化统计：补齐持续时长、速率与突发窗口。
func freezeQuantStats(ctx map[string]any) {
	raw, _ := ctx[quantStatsKey].(map[string]any)
	if raw == nil {
		return
	}
	qs := fromMap(raw)
	if qs == nil {
		return
	}
	start := parseOccurrenceTime(qs.WindowStart)
	end := parseOccurrenceTime(qs.WindowEnd)
	if !start.IsZero() && !end.IsZero() && end.After(start) {
		qs.DurationSec = int64(end.Sub(start).Seconds())
		if qs.DurationSec > 0 {
			qs.RatePerMin = float64(qs.OccurrenceCount) * 60 / float64(qs.DurationSec)
		}
	}
	qs.PeakWindow = peakWindow(ctx["occurrences"])
	ctx[quantStatsKey] = toMap(qs)
}

func newQuantStats() *domain.QuantStats {
	return &domain.QuantStats{
		ByRule:      map[string]int64{},
		ByDirection: map[string]int64{},
		ByIOC:       []domain.IocHitStat{},
		SourceIPs:   map[string]int64{},
		DestIPs:     map[string]int64{},
	}
}

// applyHitStats 把单次命中的规则/方向/IOC/体量/源目维度累加进量化统计。
func applyHitStats(qs *domain.QuantStats, ly map[string]any) {
	if v := asString(ly["rule_id"]); v != "" {
		qs.ByRule[v]++
	}
	if v := asString(ly["direction"]); v != "" {
		qs.ByDirection[v]++
	}
	if v := asString(ly["ioc_value"]); v != "" {
		iocType := asString(ly["ioc_type"])
		occ := firstNonEmpty(asString(ly["occurrence_time"]), asString(ly["time"]))
		found := false
		for i := range qs.ByIOC {
			if qs.ByIOC[i].IOCValue == v {
				qs.ByIOC[i].Count++
				if occ != "" && (qs.ByIOC[i].FirstSeen == "" || parseOccurrenceTime(occ).Before(parseOccurrenceTime(qs.ByIOC[i].FirstSeen))) {
					qs.ByIOC[i].FirstSeen = occ
				}
				if occ != "" && parseOccurrenceTime(occ).After(parseOccurrenceTime(qs.ByIOC[i].LastSeen)) {
					qs.ByIOC[i].LastSeen = occ
				}
				found = true
				break
			}
		}
		if !found {
			qs.ByIOC = append(qs.ByIOC, domain.IocHitStat{
				IOCValue:  v,
				IOCType:   iocType,
				Count:     1,
				FirstSeen: occ,
				LastSeen:  occ,
			})
		}
	}
	if v := asString(ly["src_ip"]); v != "" {
		if qs.SourceIPs[v] == 0 {
			qs.UniqueSrcIPs++
		}
		qs.SourceIPs[v]++
	}
	if v := asString(ly["dst_ip"]); v != "" {
		if qs.DestIPs[v] == 0 {
			qs.UniqueDstIPs++
		}
		qs.DestIPs[v]++
	}
	if v := toInt(ly["wire_bytes"]); v > 0 {
		qs.TotalWireBytes += int64(v)
	}
	// 载荷总字节（ta_node bytes 字段，必填）——事件列表「总载荷大小」排序口径。
	if v := toInt(ly["bytes"]); v > 0 {
		qs.TotalPayloadBytes += int64(v)
	}
	if v := toInt(ly["packets"]); v > 0 {
		qs.TotalPackets += int64(v)
	}
}

// peakWindow 从 occurrences 时间序列计算最密集的 5 分钟窗口。
func peakWindow(occurrences any) domain.PeakWindowStat {
	items, ok := occurrences.([]any)
	if !ok || len(items) == 0 {
		return domain.PeakWindowStat{}
	}
	times := make([]time.Time, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		t := parseOccurrenceTime(asString(m["time"]))
		if !t.IsZero() {
			times = append(times, t)
		}
	}
	if len(times) == 0 {
		return domain.PeakWindowStat{}
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	window := time.Duration(peakWindowSec) * time.Second
	bestStart := times[0]
	bestCount := int64(0)
	head := 0
	for tail := range times {
		for head < tail && times[tail].Sub(times[head]) > window {
			head++
		}
		count := int64(tail - head + 1)
		if count > bestCount {
			bestCount = count
			bestStart = times[head]
		}
	}
	return domain.PeakWindowStat{
		StartTime: bestStart.In(domain.Beijing).Format("2006-01-02 15:04:05"),
		EndTime:   bestStart.Add(window).In(domain.Beijing).Format("2006-01-02 15:04:05"),
		Count:     bestCount,
	}
}

// parseOccurrenceTime 兼容多种时间格式（RFC3339、MySQL 时间串、Unix epoch）。
func parseOccurrenceTime(v string) time.Time {
	return domain.ParseEventTime(v)
}

// formatQuantStats 把量化统计渲染为可读 Markdown，供分析 prompt 注入。
func formatQuantStats(raw map[string]any) string {
	qs := fromMap(raw)
	if qs == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "- 命中次数：%d\n", qs.OccurrenceCount)
	if qs.WindowStart != "" || qs.WindowEnd != "" {
		fmt.Fprintf(&b, "- 时间窗口：%s ~ %s\n", dashIfEmpty(qs.WindowStart), dashIfEmpty(qs.WindowEnd))
	}
	if qs.DurationSec > 0 {
		fmt.Fprintf(&b, "- 持续时长：%d 秒\n", qs.DurationSec)
	}
	if qs.RatePerMin > 0 {
		fmt.Fprintf(&b, "- 平均速率：%.2f 次/分钟\n", qs.RatePerMin)
	}
	if qs.TotalWireBytes > 0 || qs.TotalPackets > 0 {
		fmt.Fprintf(&b, "- 流量体量：wire_bytes=%d, packets=%d\n", qs.TotalWireBytes, qs.TotalPackets)
	}
	if qs.UniqueSrcIPs > 0 || qs.UniqueDstIPs > 0 {
		fmt.Fprintf(&b, "- 源/目标 IP 数：%d / %d\n", qs.UniqueSrcIPs, qs.UniqueDstIPs)
	}
	if len(qs.ByRule) > 0 {
		fmt.Fprintf(&b, "- 规则命中分布：%s\n", countMapString(qs.ByRule))
	}
	if len(qs.ByDirection) > 0 {
		fmt.Fprintf(&b, "- 方向分布：%s\n", countMapString(qs.ByDirection))
	}
	if len(qs.ByIOC) > 0 {
		var parts []string
		for _, ioc := range qs.ByIOC {
			parts = append(parts, fmt.Sprintf("%s(%s)x%d", ioc.IOCValue, ioc.IOCType, ioc.Count))
		}
		fmt.Fprintf(&b, "- IOC 命中：%s\n", strings.Join(parts, ", "))
	}
	if qs.PeakWindow.Count > 0 {
		fmt.Fprintf(&b, "- 最密集 5 分钟窗口：%s ~ %s，%d 次\n", qs.PeakWindow.StartTime, qs.PeakWindow.EndTime, qs.PeakWindow.Count)
	}
	return strings.TrimRight(b.String(), "\n")
}

func countMapString(m map[string]int64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

func dashIfEmpty(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func toMap(v any) map[string]any {
	raw, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func fromMap(raw map[string]any) *domain.QuantStats {
	if len(raw) == 0 {
		return nil
	}
	b, _ := json.Marshal(raw)
	var qs domain.QuantStats
	if err := json.Unmarshal(b, &qs); err != nil {
		return nil
	}
	if qs.ByRule == nil {
		qs.ByRule = map[string]int64{}
	}
	if qs.ByDirection == nil {
		qs.ByDirection = map[string]int64{}
	}
	if qs.SourceIPs == nil {
		qs.SourceIPs = map[string]int64{}
	}
	if qs.DestIPs == nil {
		qs.DestIPs = map[string]int64{}
	}
	return &qs
}
