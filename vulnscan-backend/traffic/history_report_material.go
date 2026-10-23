package traffic

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"vulnscan-backend/traffic/internal/domain"
)

type HistoryActivityDay struct {
	Date         string         `json:"date"`
	ObservedHits int            `json:"observed_hits"`
	ActiveEvents int            `json:"active_events"`
	Assets       map[string]int `json:"asset_hit_counts"`
	Endpoints    map[string]int `json:"endpoint_hit_counts"`
	Protocols    map[string]int `json:"protocol_hit_counts"`
}

type HistoryFeatures struct {
	Daily                []HistoryActivityDay `json:"daily_observed_activity"`
	Coverage             map[string]int       `json:"coverage_event_counts"`
	Protocols            map[string]int       `json:"observed_protocol_hit_counts"`
	Directions           map[string]int       `json:"saved_direction_hit_counts"`
	Endpoints            map[string]int       `json:"observed_endpoint_hit_counts"`
	Intelligence         map[string]int       `json:"saved_ioc_intelligence_event_counts"`
	Evidence             map[string]int       `json:"saved_evidence_event_counts"`
	HeartbeatEvents      int                  `json:"saved_heartbeat_events"`
	HeartbeatPeriods     map[string]int       `json:"saved_heartbeat_period_seconds_event_counts"`
	VerifiedPayloadBytes int64                `json:"verified_payload_bytes"`
	VerifiedVolumeEvents int                  `json:"verified_volume_events"`
	ReportEvents         int                  `json:"events_with_saved_evidence_report"`
	Boundaries           []string             `json:"boundaries"`
}

// Pin one saved snapshot per event and walk every page; a preview is never
// treated as complete history. Legacy arrays remain explicitly partial.
func (s *EventService) historyFeatures(ctx context.Context, events []domain.Event) (HistoryFeatures, error) {
	f := HistoryFeatures{Daily: []HistoryActivityDay{}, Coverage: map[string]int{}, Protocols: map[string]int{}, Directions: map[string]int{}, Endpoints: map[string]int{}, Intelligence: map[string]int{}, Evidence: map[string]int{}, HeartbeatPeriods: map[string]int{}, Boundaries: []string{
		"observed_hits 为已保存命中记录，不是会话或成功连接数；active_events 为当天实际有时间戳记录的事件数，不把跨日首末时间插值为活动。",
		"complete_saved_hits 仅表示已发布快照中的保存记录完整，不证明完整网络采集；legacy_partial 和 unavailable 的缺口不补零。",
		"端点按原始 dst_ip:dst_port/protocol 汇总，不等于攻击目标；DNS端点可能为解析服务器。",
		"保存的情报标签与证据结论仅作历史背景；不同事件命中同一证据不自动成为独立佐证，accepted 不等于支持恶意。",
		"只有量化数据 volume_quality=verified 时累计载荷字节；未验证数据不补零，不推断上下行流量或连接成功率。",
	}}
	days := map[string]*HistoryActivityDay{}
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return f, err
		}
		var c map[string]any
		_ = json.Unmarshal([]byte(event.Context), &c)
		row := lyCompatibleEvent(event)
		asset := firstNonEmpty(stringValue(row["victimDevice"]), "未知")
		eventDays := map[string]bool{}
		add := func(hit map[string]any) {
			at := domain.ParseEventTime(hit["time"])
			if at.IsZero() {
				f.Coverage["invalid_time_records"]++
				return
			}
			date := at.In(domain.Beijing).Format("2006-01-02")
			if days[date] == nil {
				days[date] = &HistoryActivityDay{Date: date, Assets: map[string]int{}, Endpoints: map[string]int{}, Protocols: map[string]int{}}
			}
			d := days[date]
			d.ObservedHits++
			d.Assets[asset]++
			if !eventDays[date] {
				d.ActiveEvents++
				eventDays[date] = true
			}
			protocol := strings.ToLower(firstNonEmpty(stringValue(hit["protocol"]), stringValue(hit["proto"]), "未知"))
			f.Protocols[protocol]++
			d.Protocols[protocol]++
			f.Directions[firstNonEmpty(stringValue(hit["direction"]), "未知")]++
			if ip := stringValue(hit["dst_ip"]); ip != "" {
				endpoint := fmt.Sprintf("%s:%v/%s", ip, hit["dst_port"], protocol)
				f.Endpoints[endpoint]++
				d.Endpoints[endpoint]++
			}
		}
		version := int64(0)
		cursor := ""
		read := 0
		quality := ""
		failed := false
		for {
			page, err := s.core.OccurrencesAt(ctx, event.EventID, cursor, "", 200, version)
			if err != nil {
				if ctx.Err() != nil {
					return f, ctx.Err()
				}
				failed = true
				break
			}
			if version == 0 {
				version = page.SnapshotVersion
			}
			quality = page.Quality
			for _, hit := range page.Items {
				add(hit)
				read++
			}
			if page.NextCursor == "" {
				break
			}
			cursor = page.NextCursor
		}
		switch {
		case failed:
			f.Coverage["unavailable"]++
		case quality == "verified":
			f.Coverage["complete_saved_hits"]++
		case read > 0:
			f.Coverage["legacy_partial"]++
		default:
			f.Coverage["no_saved_hit_details"]++
		}
		if heartbeat, _ := c["heartbeat_detected"].(bool); heartbeat {
			f.HeartbeatEvents++
			f.HeartbeatPeriods[fmt.Sprint(c["heartbeat_period_sec"])]++
		}
		if qs, ok := c["quant_stats"].(map[string]any); ok && qs["volume_quality"] == "verified" {
			if n, ok := qs["total_payload_bytes"].(float64); ok && n >= 0 {
				f.VerifiedPayloadBytes += int64(n)
				f.VerifiedVolumeEvents++
			}
		}
		seenIntel := map[string]bool{}
		for _, key := range []string{"ioc", "ioc_evidence"} {
			if intel, ok := c[key].(map[string]any); ok {
				for _, field := range []string{"source", "sources", "threat_type", "threat_name", "malware_family", "confidence"} {
					if value, ok := intel[field]; ok {
						raw, _ := json.Marshal(value)
						if len(raw) > 1000 {
							continue
						}
						seenIntel[field+"="+string(raw)] = true
					}
				}
			}
		}
		for tag := range seenIntel {
			f.Intelligence[tag]++
		}
		// Use only a bound saved structured report; never send per-event prose.
		doc, err := s.core.ReportDocument(ctx, event.EventID, 0)
		if err == nil {
			f.ReportEvents++
			seen := map[string]bool{}
			for _, e := range doc.Evidence.Entries {
				label := e.Name + " | " + e.Status
				if e.Finding != nil {
					label += " | " + string(e.Finding.Status)
				}
				if e.Semantic != nil {
					raw, _ := json.Marshal(e.Semantic)
					var sem map[string]any
					_ = json.Unmarshal(raw, &sem)
					for _, key := range []string{"judgement", "semantic_support", "behavior_outcome", "structure_validation"} {
						if value, ok := sem[key]; ok {
							label += " | " + key + "=" + fmt.Sprint(value)
						}
					}
				}
				seen[label] = true
			}
			for label := range seen {
				f.Evidence[label]++
			}
		}
	}
	dates := make([]string, 0, len(days))
	for date := range days {
		dates = append(dates, date)
	}
	sort.Strings(dates)
	for _, date := range dates {
		f.Daily = append(f.Daily, *days[date])
	}
	return f, nil
}
