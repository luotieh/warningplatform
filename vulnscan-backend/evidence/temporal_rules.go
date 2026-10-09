package evidence

import (
	"math"
	"sort"
)

func (e *Engine) timeFact(f Finding, g *observations) Finding {
	if !g.complete {
		return absent(f, UnverifiedCoverage)
	}
	if !g.prepareTime() {
		return absent(f, InvalidTime)
	}
	f.Window = g.window
	switch f.FactID {
	case "F_BEACON_JITTER":
		if len(g.times) < 16 {
			return absent(f, InsufficientSamples)
		}
		lag, ok := e.policy(&f, "ljung_box_lags")
		if !ok || lag < 1 || lag != math.Trunc(lag) || lag >= float64(len(g.times)-1) {
			return absent(f, MissingPolicy)
		}
		intervals := []float64{}
		for i := 1; i < len(g.times); i++ {
			intervals = append(intervals, g.times[i].Sub(g.times[i-1]).Seconds())
		}
		_, cv := moments(intervals)
		q, p, peak, _ := ljungBox(intervals, int(lag))
		med := median(intervals)
		// Median stability is measured against a second, independent subwindow.
		tolerance, ok := e.policy(&f, "median_relative_tolerance")
		if !ok || tolerance < 0 {
			return absent(f, MissingPolicy)
		}
		left, right := median(intervals[:len(intervals)/2]), median(intervals[len(intervals)/2:])
		stability := 0.0
		if med > 0 {
			stability = math.Abs(left-right) / med
		}
		return finish(f, med > 0 && cv > 0.15 && cv <= 0.40 && p < 0.05 && peak > 0.3 && stability <= tolerance, map[string]float64{"interval_cv": cv, "median_interval_sec": med, "median_relative_change": stability, "ljung_box_q": q, "p_value": p, "acf_peak": peak})
	case "F_FIXED_DAILY_WINDOW":
		days := map[string]bool{}
		seconds := []float64{}
		for _, t := range g.times {
			local := t.In(e.dayLocation)
			days[local.Format("2006-01-02")] = true
			seconds = append(seconds, float64(local.Hour()*3600+local.Minute()*60+local.Second()))
		}
		if len(days) < 3 {
			return absent(f, InsufficientSamples)
		}
		sort.Float64s(seconds)
		doubled := append(append([]float64(nil), seconds...), seconds...)
		for i := len(seconds); i < len(doubled); i++ {
			doubled[i] += 86400
		}
		best, right := 0, 0
		for left := range seconds {
			for right < len(doubled) && right < left+len(seconds) && doubled[right]-doubled[left] <= 7200 {
				right++
			}
			if right-left > best {
				best = right - left
			}
		}
		ratio := float64(best) / float64(len(seconds))
		return finish(f, ratio >= 0.8, map[string]float64{"days_active": float64(len(days)), "daily_window_fraction": ratio, "window_seconds": 7200})
	case "F_RATE_BURST", "F_RATE_RAMP":
		if g.input == nil || g.input.Window == nil {
			return absent(f, MissingInput)
		}
		w := g.input.Window
		duration := w.End.Sub(w.Start)
		if !w.Start.Before(w.End) {
			return absent(f, MissingInput)
		}
		step := 300.0
		if f.FactID == "F_RATE_RAMP" {
			v, ok := e.policy(&f, "window_seconds")
			if !ok || v <= 0 {
				return absent(f, MissingPolicy)
			}
			step = v
		}
		count := int(duration.Seconds() / step)
		if count < 1 {
			return absent(f, InsufficientSamples)
		}
		if count > 100000 || (f.FactID == "F_RATE_RAMP" && count > 128) {
			return absent(f, StatisticalConstraint)
		}
		if duration.Seconds() != float64(count)*step {
			return absent(f, MissingInput)
		}
		buckets := make([]float64, count)
		for _, t := range g.times {
			if t.Before(w.Start) || !t.Before(w.End) {
				return absent(f, UnresolvedBinding)
			}
			i := int(t.Sub(w.Start).Seconds() / step)
			buckets[i]++
		}
		f.Window = &Window{Start: w.Start.UTC(), End: w.End.UTC(), Convention: "analysis_half_open"}
		if f.FactID == "F_RATE_RAMP" {
			s, p, ok := exactKendall(buckets)
			if !ok {
				if count < 5 {
					return absent(f, InsufficientSamples)
				}
				return absent(f, StatisticalConstraint)
			}
			return finish(f, s > 0 && p < 0.05, map[string]float64{"kendall_s": float64(s), "p_value": p, "window_count": float64(count), "window_seconds": step})
		}
		b, ok := baseline(&f, g, "mean_per_5m", "burst_ratio_p99")
		if !ok || b[0] <= 0 || b[1] < 0 {
			return absent(f, MissingBaseline)
		}
		peak := 0.0
		for _, v := range buckets {
			if v > peak {
				peak = v
			}
		}
		ratio := peak / b[0]
		return finish(f, ratio > b[1], map[string]float64{"peak_count": peak, "burst_ratio": ratio, "baseline_p99": b[1]})
	}
	return absent(f, MissingInput)
}
