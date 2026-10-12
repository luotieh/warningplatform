package service

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"vulnscan-backend/evidence"
)

// A comparison policy, never a claim about the asset's actual working hours.
// End is exclusive; 08:00 is in-hours and 20:00 is off-hours. All days apply.
type ReportSchedulePolicy struct {
	StartMinute int    `json:"start_minute"`
	EndMinute   int    `json:"end_minute"`
	Source      string `json:"source"`
}

var reportDayLocation = time.FixedZone("Asia/Shanghai", 8*3600)

func reportSchedulePolicy(m SnapshotEvidenceManifest, asset string) ReportSchedulePolicy {
	if p, ok := m.ReportSchedules[asset]; ok && p.StartMinute >= 0 && p.StartMinute < 1440 && p.EndMinute > p.StartMinute && p.EndMinute <= 1440 && p.Source != "" {
		return p
	}
	return ReportSchedulePolicy{StartMinute: 480, EndMinute: 1200, Source: "报告默认工作时段规则"}
}

type reportScheduleStats struct {
	Rows        []ReportMaterialObservation
	Refs        []string
	Outside     int
	Days        []string
	Counts      map[string]int
	Consecutive int
	First, Last time.Time
	Hours       [24]int
}

func measureReportSchedule(rows []ReportMaterialObservation, p ReportSchedulePolicy) reportScheduleStats {
	s := reportScheduleStats{Counts: map[string]int{}}
	seen := map[string]bool{}
	for _, r := range rows {
		if r.HitID == "" || r.Time.IsZero() || seen[r.HitID] {
			continue
		}
		seen[r.HitID] = true
		s.Rows = append(s.Rows, r)
		s.Refs = append(s.Refs, r.HitID)
		local := r.Time.In(reportDayLocation)
		s.Counts[local.Format("2006-01-02")]++
		s.Hours[local.Hour()]++
		minute := local.Hour()*60 + local.Minute()
		if minute < p.StartMinute || minute >= p.EndMinute {
			s.Outside++
		}
		if s.First.IsZero() || r.Time.Before(s.First) {
			s.First = r.Time
		}
		if s.Last.IsZero() || r.Time.After(s.Last) {
			s.Last = r.Time
		}
	}
	for d := range s.Counts {
		s.Days = append(s.Days, d)
	}
	sort.Strings(s.Days)
	sort.Strings(s.Refs)
	streak := 0
	var previous time.Time
	for _, d := range s.Days {
		day, _ := time.ParseInLocation("2006-01-02", d, reportDayLocation)
		if !previous.IsZero() && day.Equal(previous.AddDate(0, 0, 1)) {
			streak++
		} else {
			streak = 1
		}
		if streak > s.Consecutive {
			s.Consecutive = streak
		}
		previous = day
	}
	return s
}

func scheduleText(p ReportSchedulePolicy, s reportScheduleStats) string {
	parts := []string{}
	for _, day := range s.Days {
		parts = append(parts, fmt.Sprintf("%s=%d条", day, s.Counts[day]))
	}
	return fmt.Sprintf("北京时间；比较时段=%02d:%02d—%02d:%02d（结束时刻不含）；规则来源=%s；已保存命中%d条，其中非工作时段%d条，占比%.1f%%；实际活跃%d个自然日，最长连续%d天；逐日记录：%s。统计对象是已保存命中；默认时段是报告比较规则，未登记角色不作资产角色推断；已知全天运行、授权任务和已证实正常业务应优先解释，不将时间特征单独定为攻击。", p.StartMinute/60, p.StartMinute%60, p.EndMinute/60, p.EndMinute%60, p.Source, len(s.Rows), s.Outside, 100*float64(s.Outside)/float64(len(s.Rows)), len(s.Days), s.Consecutive, strings.Join(parts, "，"))
}

func reportScheduleEvidence(m SnapshotEvidenceManifest) []ReportEvidence {
	groups := map[evidence.Scope][]ReportMaterialObservation{}
	for _, r := range m.ReportObservations {
		groups[r.Scope] = append(groups[r.Scope], r)
	}
	keys := []evidence.Scope{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return scopeKey(keys[i]) < scopeKey(keys[j]) })
	out := []ReportEvidence{}
	for _, scope := range keys {
		p := reportSchedulePolicy(m, scope.AssetID)
		s := measureReportSchedule(groups[scope], p)
		if len(s.Rows) == 0 || (s.Outside == 0 && len(s.Days) < 2) {
			continue
		}
		name := "跨日通信日期分布"
		if s.Outside > 0 {
			name = "非工作时段通信与逐日分布"
		}
		out = append(out, ReportEvidence{Kind: "observation", Name: name, Status: "observed", Result: scheduleText(p, s), Scope: scope, Window: &evidence.Window{Start: s.First.UTC(), End: s.Last.UTC()}, Source: p.Source + " / 已保存命中时间", SourceIDs: s.Refs, Family: "saved_schedule", Dependencies: []evidence.Dependency{{Kind: "schedule_policy", Version: "report-schedule-1.0", SourceIDs: []string{p.Source}}}})
	}
	return out
}

func addReportScheduleMaterials(subject *evidence.SemanticSubject, m SnapshotEvidenceManifest, factory semanticMaterialFactory) {
	rows := []ReportMaterialObservation{}
	for _, r := range m.ReportObservations {
		if r.Scope != subject.Scope || r.Time.Before(subject.Window.Start) || r.Time.After(subject.Window.End) {
			continue
		}
		rows = append(rows, r)
	}
	p := reportSchedulePolicy(m, subject.Scope.AssetID)
	stats := measureReportSchedule(rows, p)
	if len(stats.Rows) == 0 {
		return
	}
	// Provenance proves which policy and timestamps were used, not business hours.
	provenance := evidence.Provenance{Verified: true, Complete: true, Version: "report-schedule-1.0", SourceIDs: stats.Refs}
	schedule := factory(subject, "business_schedule", fmt.Sprintf("%s：北京时间%02d:%02d—%02d:%02d；这是比较规则，不是资产业务作息核验结果。", p.Source, p.StartMinute/60, p.StartMinute%60, p.EndMinute/60, p.EndMinute%60), "report.schedule_policy", provenance, true)
	schedule.Role = "report_default_workhours"
	text := scheduleText(p, stats)
	distribution := factory(subject, "time_distribution", text, "snapshot.saved_hit_times", provenance, true)
	subject.Materials = append(subject.Materials, schedule, distribution)
}
