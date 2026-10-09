package evidence

import (
	"math"
	"sort"
)

func (e *Engine) periodic(g *observations) Finding {
	p := e.config.Periodic // Copy parameters, so results never expose mutable engine configuration.
	f := baseFinding(BeaconPeriodic, g, Parameters{Periodic: &p}, []string{
		"命中时间序列不是全部连接；健康检查和遥测也可呈周期性", "周期性不能据此确认C2或主机被控"})
	if !g.complete {
		f.ReasonCode = UnverifiedCoverage
		return f
	}
	if len(g.hits) < p.MinSamples {
		f.ReasonCode = InsufficientSamples
		return f
	}
	var maxPackets uint64
	for _, hit := range g.hits {
		if hit.Packets == nil {
			f.ReasonCode = MissingPackets
			return f
		}
		if *hit.Packets > maxPackets {
			maxPackets = *hit.Packets
		}
	}
	if !g.prepareTime() {
		f.ReasonCode = InvalidTime
		return f
	}
	f.Window = g.window
	intervals := make([]float64, 0, len(g.times)-1)
	var average, m2 float64
	for i := 1; i < len(g.times); i++ {
		delta := g.times[i].Sub(g.times[i-1]).Seconds()
		intervals = append(intervals, delta)
		change := delta - average
		average += change / float64(i)
		m2 += change * (delta - average)
	}
	ordered := append([]float64(nil), intervals...)
	sort.Float64s(ordered)
	minimum, maximum := ordered[0], ordered[len(ordered)-1]
	middle := len(ordered) / 2
	med := ordered[middle]
	if len(ordered)%2 == 0 {
		med = (ordered[middle-1] + ordered[middle]) / 2
	}
	f.Measurements.MinIntervalSeconds = &minimum
	f.Measurements.MaxIntervalSeconds = &maximum
	f.Measurements.MedianIntervalSeconds = &med
	f.Measurements.MaxPackets = &maxPackets
	valid := false
	if average > 0 {
		cv := math.Sqrt(math.Max(0, m2/float64(len(intervals)))) / average // Population SD, matching v0.1.
		f.Measurements.IntervalCV = &cv
		valid = cv <= p.MaxIntervalCV && minimum >= p.MinIntervalSeconds && maximum <= p.MaxIntervalSeconds && maxPackets <= p.MaxPacketsPerObservation
	}
	f.Status, f.Eligibility, f.ReasonCode = NotObserved, "eligible", ConditionsNotMet
	if valid {
		f.Status, f.ReasonCode = Observed, ConditionsMet
	}
	return f
}

func (e *Engine) multiDay(g *observations) Finding {
	p := e.config.MultiDay
	f := baseFinding(MultiDayPersist, g, Parameters{MultiDay: &p}, []string{
		"仅表示观察窗口内跨日活跃，不证明连续连接或长期植入", "覆盖不足不能排除其他活跃日"})
	if !g.prepareTime() {
		f.ReasonCode = InvalidTime
		return f
	}
	f.Window = g.window
	days := make(map[string]struct{})
	for _, t := range g.times {
		days[t.In(e.dayLocation).Format("2006-01-02")] = struct{}{}
	}
	count := len(days)
	f.Measurements.DaysActive = &count
	if count >= p.MinDays {
		f.Status, f.Eligibility, f.ReasonCode = Observed, "eligible", ConditionsMet
	} else if !g.complete {
		f.ReasonCode = IncompleteNegative
	} else {
		f.Status, f.Eligibility, f.ReasonCode = NotObserved, "eligible", ConditionsNotMet
	}
	return f
}
