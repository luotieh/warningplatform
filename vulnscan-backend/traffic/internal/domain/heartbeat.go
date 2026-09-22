package domain

import (
	"sort"
	"time"
)

// HeartbeatObservation 心跳判定所需的最小命中观测：发生时间与包数。
type HeartbeatObservation struct {
	At      time.Time
	Packets float64
}

// DetectHeartbeat 判定 C2 信标心跳（固定周期小包通信）。刻意严格：
// >=8 次观测、周期 5s..24h、变异系数 <=15%、跨度不少于 3 个周期、
// 每次观测 <=5 个包。普通或样本不足的流量返回 false。
func DetectHeartbeat(obs []HeartbeatObservation) (bool, int64) {
	ts := make([]time.Time, 0, len(obs))
	for _, o := range obs {
		if o.Packets > 5 {
			return false, 0
		}
		if !o.At.IsZero() {
			ts = append(ts, o.At)
		}
	}
	if len(ts) < 8 {
		return false, 0
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	intervals := make([]float64, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		d := ts[i].Sub(ts[i-1]).Seconds()
		if d < 5 || d > 86400 {
			return false, 0
		}
		intervals = append(intervals, d)
	}
	mean := 0.0
	for _, d := range intervals {
		mean += d
	}
	mean /= float64(len(intervals))
	if ts[len(ts)-1].Sub(ts[0]).Seconds() < mean*3 {
		return false, 0
	}
	variance := 0.0
	for _, d := range intervals {
		x := d - mean
		variance += x * x
	}
	variance /= float64(len(intervals))
	if variance > (mean*0.15)*(mean*0.15) {
		return false, 0
	}
	return true, int64(mean + 0.5)
}
