package traffic

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"sort"
	"strings"
)

const historyActivityInstructions = `
优先使用 connection_features.daily_observed_activity 分析按日活动：observed_hits 为当日保存命中数，active_events 为当天有实际记录的事件数。跨日事件在实际有记录的每一天分别统计。daily_event_starts 仅为新增聚合事件数，不能代替活动强度。
必须说明 coverage_event_counts 的完整、旧版部分明细和不可用事件数。缺失日期不等于无活动；只有 complete_saved_hits 表示已发布快照保存记录完整，不等于全网流量完整。不得将缺口补零。
比较每日端点、协议、资产变化，结合保存的心跳周期、IOC情报和证据结论解释历史背景。证据按事件去重，标签重复不代表独立佐证，accepted 不等于恶意。已保存的情报和证据可能过期；不能替代当前验证。
只使用已验证的载荷量，未保存的上下行、连接成功失败、会话结果写为未知，不杜撰成功率或外传量。`

type historyReportArchive struct {
	ReportID string                `json:"report_id"`
	Kind     string                `json:"kind"`
	Markdown string                `json:"markdown"`
	Snapshot HistoryReportSnapshot `json:"snapshot"`
}

// Reading saved reports never invokes the model. Include legacy records whose
// group was empty so reports created by the first release remain discoverable.
func (h *Handler) ListHistoryReports(c *gin.Context) {
	scope := HistoryReportScope{IOCValue: strings.TrimSpace(c.Query("ioc_value")), IOCType: strings.TrimSpace(c.Query("ioc_type")), Victim: strings.TrimSpace(c.Query("victim"))}
	if scope.IOCValue == "" {
		fail(c, 400, "请提供 IOC 查询范围")
		return
	}
	records, err := h.events.core.Store.AggregateRecords(c.Request.Context(), "history_report", "", 0)
	if err != nil {
		fail(c, 500, "读取综合报告列表失败")
		return
	}
	type item struct {
		ReportID    string             `json:"report_id"`
		GeneratedAt string             `json:"generated_at"`
		EventCount  int                `json:"event_count"`
		Scope       HistoryReportScope `json:"scope"`
	}
	items := []item{}
	for _, r := range records {
		var doc historyReportArchive
		if json.Unmarshal(r.Value, &doc) != nil || doc.Kind != "history_comprehensive" {
			continue
		}
		saved := doc.Snapshot.Scope
		if !strings.EqualFold(scope.IOCValue, saved.IOCValue) || !strings.EqualFold(scope.IOCType, saved.IOCType) || !strings.EqualFold(scope.Victim, saved.Victim) {
			continue
		}
		items = append(items, item{r.Key, doc.Snapshot.GeneratedAt, doc.Snapshot.EventCount, saved})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].GeneratedAt == items[j].GeneratedAt {
			return items[i].ReportID > items[j].ReportID
		}
		return items[i].GeneratedAt > items[j].GeneratedAt
	})
	ok(c, items)
}

func (h *Handler) GetHistoryReport(c *gin.Context) {
	id := c.Param("reportID")
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		fail(c, 400, "无效的综合报告编号")
		return
	}
	record, found, err := h.events.core.Store.AggregateRecord(c.Request.Context(), "history_report", id)
	if err != nil {
		fail(c, 500, "读取综合报告失败")
		return
	}
	if !found {
		fail(c, 404, "综合报告不存在")
		return
	}
	var doc historyReportArchive
	if json.Unmarshal(record.Value, &doc) != nil || doc.Kind != "history_comprehensive" {
		fail(c, 500, "综合报告记录损坏")
		return
	}
	var result map[string]any
	_ = json.Unmarshal(record.Value, &result)
	result["report_id"] = id
	ok(c, result)
}
