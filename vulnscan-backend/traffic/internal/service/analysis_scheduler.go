package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

// ConvergenceIdleWindow 聚合收敛窗口：距最近一次命中超过该时长无新增，即判定收敛。
// 与 traffic 包内列表侧的 aggregateIdleWindow 保持一致。
const ConvergenceIdleWindow = 30 * time.Minute

// ScanConverged 扫描未收敛事件，满足静默超时条件时：
//  1. 置 aggregation_closed=true 并冻结 quant_stats；
//  2. 若尚未生成终版分析（analysis_version<2），异步触发收敛终报。
//
// 返回新触发终报的事件数。
func (s Services) ScanConverged(ctx context.Context) (int, error) {
	now := time.Now().UTC()
	events := s.Store.ListEventsConvergedDue(now.Add(-ConvergenceIdleWindow))
	scheduled := 0
	for i := range events {
		ev := events[i]
		if ev.AggregationClosed {
			continue
		}
		lastSeen := eventLastSeen(ev)
		if now.Sub(lastSeen) < ConvergenceIdleWindow {
			continue
		}
		ctxMap := decodeEventContext(ev.Context)
		freezeQuantStats(ctxMap)
		ctxJSON, _ := json.Marshal(ctxMap)
		s.Store.UpdateEvent(ev.EventID, map[string]any{
			"context":            string(ctxJSON),
			"aggregation_closed": true,
		})
		if ev.AnalysisVersion < 2 {
			s.RunFinalAnalysisAsync(ev.EventID)
			scheduled++
		}
	}
	return scheduled, nil
}

// ArchiveConvergedEvents 每日归档：把已收敛且最后活跃早于今日 00:00（Asia/Shanghai）
// 的未归档事件按最后活跃日标记归档。分批执行并记录 archive_jobs 审计。
func (s Services) ArchiveConvergedEvents(ctx context.Context) (int, error) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		loc = time.UTC
	}
	nowLocal := time.Now().In(loc)
	todayStartLocal := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), 0, 0, 0, 0, loc)
	threshold := todayStartLocal.UTC()
	job := domain.ArchiveJob{
		JobID:  newID("arc"),
		Period: todayStartLocal.Format("2006-01-02"),
		Status: "running",
	}
	job, _ = s.Store.SaveArchiveJob(job)

	total := 0
	for {
		n, err := s.Store.ArchiveConvergedEvents(threshold, 500)
		if err != nil {
			job.Status = "failed"
			job.Error = err.Error()
			job.Total = total
			job.Processed = total
			_, _ = s.Store.SaveArchiveJob(job)
			return total, err
		}
		total += n
		if n == 0 {
			break
		}
		if total >= 100000 { // 安全上限，避免单日任务无限循环
			break
		}
	}
	job.Status = "success"
	job.Total = total
	job.Processed = total
	_, _ = s.Store.SaveArchiveJob(job)
	return total, nil
}

func eventLastSeen(ev domain.Event) time.Time {
	if ev.LastSeenAt != nil {
		return *ev.LastSeenAt
	}
	ctxMap := decodeEventContext(ev.Context)
	if v := asString(ctxMap["last_seen_at"]); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
	}
	return ev.UpdatedAt
}

func decodeEventContext(raw string) map[string]any {
	ctxMap := map[string]any{}
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &ctxMap)
	}
	return ctxMap
}

// GenerateAssetMonthlySummaries 对启用 IP 资产生成指定月份（period=YYYY-MM）的
// 月度总结：聚合该 IP 窗口内所有落档报告的量化指标，并由 LLM 生成叙事总结。
func (s Services) GenerateAssetMonthlySummaries(ctx context.Context, period string) ([]domain.AssetReportSummary, error) {
	return s.GenerateAssetMonthlySummariesWithProgress(ctx, period, nil)
}

// GenerateAssetMonthlySummariesWithProgress 带逐资产进度回调的月度总结生成。
// onProgress(done, total) 每完成一个资产调用一次（可为 nil）。
func (s Services) GenerateAssetMonthlySummariesWithProgress(ctx context.Context, period string, onProgress func(done int, total int)) ([]domain.AssetReportSummary, error) {
	start, err := time.Parse("2006-01", period)
	if err != nil {
		return nil, fmt.Errorf("period 格式应为 YYYY-MM: %w", err)
	}
	start = start.UTC()
	end := start.AddDate(0, 1, 0)

	assets := s.Store.ListAssets()
	now := time.Now().UTC()
	out := make([]domain.AssetReportSummary, 0, len(assets))
	done := 0
	total := 0

	for _, asset := range assets {
		if asset.AssetType != "ip" || asset.Status != 1 {
			continue
		}
		total++
		events := s.Store.ListEventsByTargetIP(asset.Address, start, end)
		summary := buildAssetMonthlySummary(asset, period, start, end, events, now)
		summary.Narrative = s.monthlyNarrative(ctx, asset, period, summary)
		summary.Status = "completed"
		saved, err := s.Store.SaveAssetReportSummary(summary)
		if err != nil {
			return out, fmt.Errorf("保存资产月度总结 %s/%s: %w", asset.Address, period, err)
		}
		out = append(out, saved)
		done++
		if onProgress != nil {
			onProgress(done, total)
		}
	}
	return out, nil
}

func buildAssetMonthlySummary(asset domain.Asset, period string, start, end time.Time, events []domain.Event, now time.Time) domain.AssetReportSummary {
	stats := domain.AssetMonthlyStats{
		BySeverity:  map[string]int{},
		ByEventType: map[string]int{},
		ByStatus:    map[string]int{},
	}
	summary := domain.AssetReportSummary{
		ID:         newID("ars"),
		AssetID:    asset.ID,
		AssetIP:    asset.Address,
		Period:     period,
		WindowFrom: start.Format("2006-01-02 15:04:05"),
		WindowTo:   end.Format("2006-01-02 15:04:05"),
		Status:     "pending",
		CreatedAt:  now,
	}
	for i := range events {
		ev := events[i]
		if !isFiledReport(ev) || !eventTargetsIP(ev, asset.Address) {
			continue
		}
		ctxMap := decodeEventContext(ev.Context)
		lastTime := asString(ctxMap["last_time"])
		if lastTime == "" {
			if qs, ok := ctxMap[quantStatsKey].(map[string]any); ok {
				lastTime = asString(qs["window_end"])
			}
		}
		t := parseOccurrenceTime(lastTime)
		if t.IsZero() {
			t = ev.UpdatedAt
		}
		if t.Before(start) || !t.Before(end) {
			continue
		}

		summary.EventCount++
		stats.BySeverity[firstNonEmpty(ev.Severity, "unknown")]++
		stats.ByEventType[firstNonEmpty(asString(ctxMap["event_type"]), "unknown")]++
		if ev.CircularCode != "" {
			stats.ByStatus["closed"]++
			stats.ClosedCount++
		} else {
			stats.ByStatus[firstNonEmpty(ev.ReviewStatus, "unreviewed")]++
		}
		if qs := quantStatsFromContext(ctxMap); qs != nil {
			stats.TotalOccurrences += qs.OccurrenceCount
			stats.TotalWireBytes += qs.TotalWireBytes
			for src, c := range qs.SourceIPs {
				stats.TopSources = appendCount(stats.TopSources, src, int(c))
			}
			for rule, c := range qs.ByRule {
				stats.TopRules = appendCount(stats.TopRules, rule, int(c))
			}
			for _, ioc := range qs.ByIOC {
				stats.TopIOCs = appendCount(stats.TopIOCs, ioc.IOCValue, int(ioc.Count))
			}
		}
		if stats.FirstEventTime == "" || lastTime < stats.FirstEventTime {
			stats.FirstEventTime = lastTime
		}
		if lastTime > stats.LastEventTime {
			stats.LastEventTime = lastTime
		}
	}
	stats.TopSources = topCountItems(stats.TopSources, 10)
	stats.TopIOCs = topCountItems(stats.TopIOCs, 10)
	stats.TopRules = topCountItems(stats.TopRules, 10)
	summary.Stats = stats
	return summary
}

// isFiledReport 落档报告：事件已收敛（有终版）或已推送通报处置。
func isFiledReport(ev domain.Event) bool {
	return ev.AggregationClosed || ev.CircularCode != ""
}

func eventTargetsIP(ev domain.Event, ip string) bool {
	ctxMap := decodeEventContext(ev.Context)
	for _, key := range []string{"dst_ip", "victim_target"} {
		if strings.TrimSpace(strings.ToLower(asString(ctxMap[key]))) == strings.ToLower(strings.TrimSpace(ip)) {
			return true
		}
	}
	for _, obs := range ev.Observables {
		if obs.Role == "destination" && strings.EqualFold(obs.Value, ip) {
			return true
		}
	}
	return false
}

func quantStatsFromContext(ctxMap map[string]any) *domain.QuantStats {
	if raw, ok := ctxMap[quantStatsKey].(map[string]any); ok {
		return fromMap(raw)
	}
	return nil
}

func appendCount(items []domain.CountItem, value string, count int) []domain.CountItem {
	if strings.TrimSpace(value) == "" || count <= 0 {
		return items
	}
	for i := range items {
		if items[i].Value == value {
			items[i].Count += count
			return items
		}
	}
	return append(items, domain.CountItem{Value: value, Count: count})
}

func topCountItems(items []domain.CountItem, n int) []domain.CountItem {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Value < items[j].Value
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}

// monthlyNarrative 调用 LLM 生成月度总结叙事；LLM 不可用时返回量化统计说明。
func (s Services) monthlyNarrative(ctx context.Context, asset domain.Asset, period string, summary domain.AssetReportSummary) string {
	if s.LLM == nil {
		return "（LLM 未配置，仅生成量化统计）"
	}
	health := s.LLM.HealthCheck(ctx)
	if !health.Configured || !health.OK {
		return "（LLM 未配置或不可用，仅生成量化统计）"
	}
	reply, err := s.LLM.Chat(ctx, assetMonthlySystemPrompt, assetMonthlyPrompt(asset, period, summary))
	if err != nil {
		return fmt.Sprintf("（LLM 月度总结失败：%v；量化统计已生成）", err)
	}
	return strings.TrimSpace(reply)
}

const assetMonthlySystemPrompt = `你是安全运营月度报告分析师。仅基于给定的资产量化统计撰写月度总结，不得编造未提供的数字或事件。输出简体中文 Markdown，先给结论再展开。`

func assetMonthlyPrompt(asset domain.Asset, period string, summary domain.AssetReportSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 资产月度安全总结任务\n")
	fmt.Fprintf(&b, "资产名称：%s\n", asset.Name)
	fmt.Fprintf(&b, "资产IP：%s\n", asset.Address)
	fmt.Fprintf(&b, "统计月份：%s\n", period)
	fmt.Fprintf(&b, "窗口：%s ~ %s\n\n", summary.WindowFrom, summary.WindowTo)
	fmt.Fprintf(&b, "## 量化统计（权威依据，不得改动）\n")
	fmt.Fprintf(&b, "- 落档报告数：%d（其中已闭环 %d）\n", summary.EventCount, summary.Stats.ClosedCount)
	fmt.Fprintf(&b, "- 总命中次数：%d\n", summary.Stats.TotalOccurrences)
	fmt.Fprintf(&b, "- 总体量：%d wire_bytes\n", summary.Stats.TotalWireBytes)
	fmt.Fprintf(&b, "- 严重级别分布：%s\n", countItemString(summary.Stats.BySeverity))
	fmt.Fprintf(&b, "- 事件类型分布：%s\n", countItemString(summary.Stats.ByEventType))
	fmt.Fprintf(&b, "- 处置状态分布：%s\n", countItemString(summary.Stats.ByStatus))
	fmt.Fprintf(&b, "- 攻击源 Top：%s\n", countItemString(summary.Stats.TopSources))
	fmt.Fprintf(&b, "- IOC Top：%s\n", countItemString(summary.Stats.TopIOCs))
	fmt.Fprintf(&b, "- 规则 Top：%s\n\n", countItemString(summary.Stats.TopRules))
	b.WriteString("## 输出要求\n")
	b.WriteString("按以下结构输出：\n")
	b.WriteString("【结论】一句话概括该资产本月风险态势\n")
	b.WriteString("## 月度风险趋势\n## 重点事件\n## 建议处置\n## 信息缺口\n")
	return b.String()
}

func countItemString(v any) string {
	switch items := v.(type) {
	case map[string]int:
		keys := make([]string, 0, len(items))
		for k := range items {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, items[k]))
		}
		return strings.Join(parts, ", ")
	case []domain.CountItem:
		parts := make([]string, 0, len(items))
		for _, it := range items {
			parts = append(parts, fmt.Sprintf("%s=%d", it.Value, it.Count))
		}
		return strings.Join(parts, ", ")
	default:
		return "-"
	}
}
